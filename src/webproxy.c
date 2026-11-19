// webproxy.c — see webproxy.h. One thread over pepenet-tls's proxy core:
// ca_root_ensure (persists ~/.pepenet/pepenet-root-pepe.{crt,key}) →
// resolver_open (own WAL read handles on the shared dns store + chain db) →
// proxy_serve_ctl on 127.0.0.1:8443 with ProxyEvents feeding the mint ring.
#include "webproxy.h"
#include "appconf.h"
#include "appinst.h"
#include "dnsnet.h"
#include "platform.h"

#include "ca.h"
#include "proxy.h"
#include "resolve.h"
/* dane-08: the fold-db readers (indexer/src/db.h). Declared here, not
 * included, because db.h pulls the protocol's sha256.h whose SHA256_CTX
 * clashes with OpenSSL's in this translation unit. */
#include <sqlite3.h>
sqlite3 *idx_db_open_ro(const char *path);
void idx_db_close(sqlite3 *db);
int  idx_db_resolve(sqlite3 *db, const char *name, char owner_hex[41], char *state_out);
int  idx_db_owned(sqlite3 *db, const char *h160hex,
                  void (*cb)(void *u, const char *name, int64_t lease_expiry, int st), void *u);
int64_t idx_db_names(sqlite3 *db, const char *prefix, int64_t offset, int limit,
                     void (*cb)(void *u, const char *name, const uint8_t *owner,
                                int64_t lease_expiry, int st, uint64_t price), void *u);

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <ctype.h>
#include <stdint.h>

struct Webproxy {
    pthread_t th;
    volatile int stop;
    int started, running, ca_ready;
    int proxy_port, pac_port, pf_port;
    int combined;
    int passthrough;                // GreatDANE M3: opt-in raw CONNECT + /gd/tlsa
    char tld[16];
    char dot_tld[8];
    char data_name[32];
    char data_dir_override[512];

    X509     *root;
    EVP_PKEY *rootkey;
    Resolver *rv;
    char      chain_db[600];    // dane-08: read-only /gd/name, /gd/owned
    int       lfd;
    pthread_t thpac;                // PAC + CONNECT front door (APP_PAC_PORT):
    int       lfdpac, runningpac;   // the browser path that needs no DNS at all
#ifdef _WIN32
    pthread_t th443;                // browsers dial <name>:443 — no pf on
    int       lfd443, running443;   // Windows, but no privileged ports either:
                                    // bind it directly, best-effort
#else
    pthread_t thpf;                 // mac pf / Linux nft rdr target
    int       lfdpf, runningpf;     // (APP_PROXY_PF_PORT). :443 redirects land
                                    // here and ONLY here — pf/nft break direct
                                    // dials to the rdr target, so this port
                                    // must never be dialed (see appconf.h);
                                    // internal dials use lfd/8443
#endif

    pthread_mutex_t mu;
    int64_t conns, dane_ok, dane_fail;
    struct { char sni[64]; char origin[64]; int64_t t; int ok; } mint[WEB_MINT_LOG];
    int nmint;
};
static struct Webproxy g_store = {
    .mu = PTHREAD_MUTEX_INITIALIZER,
    .lfd = -1,
    .proxy_port = APP_PROXY_PORT,
    .pac_port = APP_PAC_PORT,
    .pf_port = APP_PROXY_PF_PORT,
    .tld = APP_TLD,
    .dot_tld = APP_DOT_TLD,
    .data_name = APP_DATA_DIR,
};
static struct Webproxy *g = &g_store;

// ProxyEvents land on the per-connection threads — ring writes under the lock
static void ev_minted(void *u, const char *sni) {
    (void)u;
    pthread_mutex_lock(&g->mu);
    g->conns++;
    memmove(g->mint + 1, g->mint, (WEB_MINT_LOG - 1) * sizeof g->mint[0]);
    snprintf(g->mint[0].sni, sizeof g->mint[0].sni, "%s", sni);
    g->mint[0].origin[0] = 0;
    g->mint[0].t = (int64_t)time(NULL);
    g->mint[0].ok = -1;                          // verdict pending
    if (g->nmint < WEB_MINT_LOG) g->nmint++;
    pthread_mutex_unlock(&g->mu);
}

static void ev_verdict(void *u, const char *sni, int dane_ok, const char *origin) {
    (void)u;
    pthread_mutex_lock(&g->mu);
    if (dane_ok) g->dane_ok++; else g->dane_fail++;
    for (int i = 0; i < g->nmint; i++)           // stamp the matching mint row
        if (g->mint[i].ok == -1 && strcmp(g->mint[i].sni, sni) == 0) {
            g->mint[i].ok = dane_ok;
            snprintf(g->mint[i].origin, sizeof g->mint[i].origin, "%s", origin ? origin : "");
            break;
        }
    pthread_mutex_unlock(&g->mu);
}

static void ev_sync(void *u, int64_t *h, int64_t *ph) {
    (void)u;
    resolver_sync(g->rv, h, ph);
}

static const ProxyEvents EV = { .minted = ev_minted, .verdict = ev_verdict, .sync = ev_sync };

/* GreatDANE --dane-api (passthrough): no root CA exists in this mode, so the
 * TLS-terminating acceptors must never reach proxy_serve_ctl with a NULL root.
 * They stay bound (the ready line reports their ports, as before) but every
 * connection is closed at once; the browser's path is the PAC port's raw
 * CONNECT + /gd/tlsa, which needs no root. Normal mode never gets here. */
static void refuse_serve(int lfd) {
    while (!g->stop) {
        struct pollfd pfd = { lfd, POLLIN, 0 };
        int pr = poll(&pfd, 1, 500);
        if (pr <= 0 || g->stop) continue;
        int cfd = accept(lfd, NULL, NULL);
        if (cfd >= 0) close(cfd);
    }
}

static void serve_tls(int lfd) {
    if (!g->ca_ready) { refuse_serve(lfd); return; }
    proxy_serve_ctl(lfd, g->root, g->rootkey, resolver_resolve, g->rv, &EV, &g->stop);
}

static void *proxy_main(void *arg) {
    (void)arg;
    serve_tls(g->lfd);
    g->running = 0;
    return NULL;
}

#ifdef _WIN32
// second acceptor on :443 — same shared state (the per-connection threads
// already assume it is safe to share; resolve.c carries the mutexes)
static void *proxy443_main(void *arg) {
    (void)arg;
    serve_tls(g->lfd443);
    g->running443 = 0;
    return NULL;
}
#else
// second acceptor on the pf rdr target — same shared state (see proxy443_main)
static void *proxypf_main(void *arg) {
    (void)arg;
    serve_tls(g->lfdpf);
    g->runningpf = 0;
    return NULL;
}
#endif

// ── PAC + CONNECT front door (127.0.0.1:APP_PAC_PORT, both platforms) ────────
// Every resolver-riding path is fragile somewhere: DNS-leak-blocking VPNs
// (Proton, Mullvad, …) install WFP filters that drop EVERY port-53 packet —
// loopback included — killing the Windows NRPT route; DoH browsers skip
// /etc/resolver entirely; mac pf loopback rdr is unreliable and an
// unprivileged process cannot bind a SPECIFIC loopback address below 1024
// (wildcard only), so a local web server on *:443 silently shadows every
// .<tld> site. This listener takes both DNS and :443 out of the loop:
// sysinstall registers http://127.0.0.1:<pacport>/proxy.pac as the system
// proxy autoconfig (HKCU AutoConfigURL / networksetup -setautoproxyurl), the
// PAC steers *.<tld> at "PROXY 127.0.0.1:<pacport>" (everything else DIRECT),
// and the browser sends CONNECT carrying the literal name. We answer 200 and
// splice the socket into the resident :8443 DANE proxy — the TLS ClientHello
// (SNI and all) flows through untouched, so minting/DANE work as on any path.
// Plain http:// requests are bounced to https (parity with the dead :80).

// SMAppService login items are jetsam-classified as daemons with a 32-thread
// cap. Each PAC CONNECT used to pthread_create+detach with no bound, and the
// DANE proxy does the same per TLS conn — Discover favicons + a browser tab
// walked the process into that cap and the app vanished with no crash report.
#define PAC_CONN_MAX 8
static volatile int g_pac_live;

static void nosigpipe(int fd) {
#ifdef SO_NOSIGPIPE
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
}

static int fd_write_all(int fd, const char *p, size_t n) {
    size_t done = 0;
    while (done < n) {
#ifdef MSG_NOSIGNAL
        ssize_t w = send(fd, p + done, n - done, MSG_NOSIGNAL);
#else
        ssize_t w = send(fd, p + done, n - done, 0);
#endif
        if (w <= 0) return -1;
        done += (size_t)w;
    }
    return 0;
}

// scan the ACTUAL bytes (network input is not a C string — a strstr() here
// goes blind at the first embedded NUL and the head is never found)
static const char *mem_find(const char *p, size_t n, const char *pat, size_t pl) {
    if (n < pl) return NULL;
    for (size_t i = 0; i + pl <= n; i++)
        if (memcmp(p + i, pat, pl) == 0) return p + i;
    return NULL;
}

// accumulate until the blank line; returns total bytes (head + any pipelined
// residue) or -1. buf is NUL-terminated AND free of embedded NULs on success,
// which is what makes the strstr/strncmp/sscanf parsing in pac_conn sound.
static int http_head_read(int fd, char *buf, size_t cap) {
    size_t n = 0, scanned = 0;
    while (n < cap - 1) {
        ssize_t r = recv(fd, buf + n, cap - 1 - n, 0);
        if (r <= 0) return -1;
        n += (size_t)r;
        buf[n] = 0;
        // a NUL before the terminator is never a legal request head (a bare
        // TLS ClientHello, a smuggled "CONNECT foo\0bar.pepe") — drop it now
        // instead of stalling to the 5 s SO_RCVTIMEO with a thread pinned
        if (memchr(buf, 0, n)) return -1;
        size_t from = scanned > 3 ? scanned - 3 : 0;       // straddling matches
        if (mem_find(buf + from, n - from, "\r\n\r\n", 4)) return (int)n;
        scanned = n;
    }
    return -1;
}

static void http_status(int fd, const char *status) {
    char b[160];
    int n = snprintf(b, sizeof b,
                     "HTTP/1.1 %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                     status);
    fd_write_all(fd, b, (size_t)n);
}

static int suffix_is(const char *s, const char *suf) {
    size_t ls = strlen(s), lf = strlen(suf);
    if (ls <= lf) return 0;                     // at least one label before it
    s += ls - lf;
    for (; *suf; s++, suf++)
        if (tolower((unsigned char)*s) != tolower((unsigned char)*suf)) return 0;
    return 1;
}

static void pac_send(int fd) {
    /* Default desktop PAC is this compile-time string: one suffix, the PAC
     * port (the CONNECT door), not the TLS DANE port. Combined mode lists
     * both suffixes and still returns THIS door; CONNECT splices by suffix
     * to each chain's DANE proxy. */
    static const char def[] =
        "function FindProxyForURL(url, host) {\n"
        "  if (dnsDomainIs(host, \"" APP_DOT_TLD "\"))\n"
        "    return \"PROXY 127.0.0.1:" APP_PAC_PORT_S "\";\n"
        "  return \"DIRECT\";\n"
        "}\n";
    char dyn[640];
    const char *body = def;
    size_t blen = sizeof def - 1;
    if (g->combined) {
        const AppInstance *pep = app_instance_by_coin("pep");
        const AppInstance *doge = app_instance_by_coin("doge");
        int n = snprintf(dyn, sizeof dyn,
            "function FindProxyForURL(url, host) {\n"
            "  if (dnsDomainIs(host, \".%s\"))\n"
            "    return \"PROXY 127.0.0.1:%d\";\n"
            "  if (dnsDomainIs(host, \".%s\"))\n"
            "    return \"PROXY 127.0.0.1:%d\";\n"
            "  return \"DIRECT\";\n"
            "}\n",
            pep ? pep->tld : "pepe", g->pac_port,
            doge ? doge->tld : "doge", g->pac_port);
        if (n > 0) { body = dyn; blen = (size_t)n; }
    }
    char head[256];
    int hn = snprintf(head, sizeof head,
                      "HTTP/1.1 200 OK\r\n"
                      "Content-Type: application/x-ns-proxy-autoconfig\r\n"
                      "Content-Length: %u\r\n"
                      "Cache-Control: no-store, no-cache\r\n"
                      "Connection: close\r\n\r\n",
                      (unsigned)blen);
    if (fd_write_all(fd, head, (size_t)hn) == 0)
        fd_write_all(fd, body, blen);
}

/* 1 if host is a name this door may tunnel. *proxy_out is the DANE port to
 * splice to. Combined: .pepe → pep proxy, .doge → doge proxy. */
static int proxy_for_host(const char *host, int *proxy_out) {
    if (!g->combined) {
        if (!suffix_is(host, g->dot_tld)) return 0;
        if (proxy_out) *proxy_out = g->proxy_port;
        return 1;
    }
    const char *ids[2] = { "pep", "doge" };
    for (int i = 0; i < 2; i++) {
        const AppInstance *inst = app_instance_by_coin(ids[i]);
        if (!inst) continue;
        char dot[8];
        snprintf(dot, sizeof dot, ".%s", inst->tld);
        if (suffix_is(host, dot)) {
            if (proxy_out) *proxy_out = inst->proxy_port;
            return 1;
        }
    }
    return 0;
}

static int dial_loopback(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    nosigpipe(fd);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) { close(fd); return -1; }
    return fd;
}

static int pump_raw(int from, int to) {
    char buf[16384];
    ssize_t n = recv(from, buf, sizeof buf, 0);
    if (n <= 0) return 0;
    for (ssize_t off = 0; off < n; ) {
#ifdef MSG_NOSIGNAL
        ssize_t w = send(to, buf + off, (size_t)(n - off), MSG_NOSIGNAL);
#else
        ssize_t w = send(to, buf + off, (size_t)(n - off), 0);
#endif
        if (w <= 0) return 0;
        off += w;
    }
    return 1;
}

static void splice_raw(int a, int b) {
    /* poll(), not select(): FD_SET on a descriptor >= FD_SETSIZE (1024) writes
     * past the 128-byte fd_set on this connection thread's stack, and select()
     * with nfds > FD_SETSIZE fails outright with EINVAL, silently killing the
     * tunnel. Each CONNECT holds two fds, so a busy front door reaches that.
     * pacd_main already polls; this is the one place that did not. */
    time_t last = time(NULL);
    for (;;) {
        if (g->stop) break;
        struct pollfd pf[2] = { { a, POLLIN, 0 }, { b, POLLIN, 0 } };
        int pr = poll(pf, 2, 500);
        if (pr < 0) break;
        if (g->stop) break;
        if (pr == 0) {
            if (time(NULL) - last >= 120) break;
            continue;
        }
        last = time(NULL);
        if ((pf[0].revents & (POLLIN | POLLHUP | POLLERR)) && !pump_raw(a, b)) break;
        if ((pf[1].revents & (POLLIN | POLLHUP | POLLERR)) && !pump_raw(b, a)) break;
    }
}

// ---- GreatDANE M3 (opt-in, --dane-api): the browser verifies DANE itself. ---
// The node never terminates TLS in this mode: CONNECT splices raw TCP to the
// chain A record, and GET /gd/tlsa?host= hands the browser the on-chain TLSA.
static const char *res_name(int rc) {
    switch (rc) {
    case RES_OK: return "ok";
    case RES_UNOWNED: return "unowned";
    case RES_NO_TLSA: return "no_tlsa";
    case RES_BAD_RECORD: return "bad_record";
    default: return "bad_name";
    }
}

static int dial_origin(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    nosigpipe(fd);
    struct timeval tv = { 10, 0 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) { close(fd); return -1; }
    struct timeval z = { 0, 0 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &z, sizeof z);
    return fd;
}

static void tlsa_api(int cfd, const char *q) {
    char host[128] = "";
    size_t n = 0;
    for (; q[n] && q[n] != ' ' && q[n] != '&' && n < sizeof host - 1; n++) {
        char c = (char)tolower((unsigned char)q[n]);
        if (!(isalnum((unsigned char)c) || c == '.' || c == '-')) { n = 0; break; }
        host[n] = c;
    }
    host[n] = 0;
    char body[1024];
    int64_t h = 0, ph = 0;
    resolver_sync(g->rv, &h, &ph);
    int bn;
    if (!n || !proxy_for_host(host, NULL) || !g->rv) {
        bn = snprintf(body, sizeof body, "{\"host\":\"%s\",\"status\":\"bad_name\"}", host);
    } else {
        OriginInfo oi;
        memset(&oi, 0, sizeof oi);
        int rc = resolver_lookup(host, &oi, g->rv);
        bn = snprintf(body, sizeof body,
                      "{\"host\":\"%s\",\"status\":\"%s\",\"height\":%lld,\"peer_height\":%lld",
                      host, res_name(rc), (long long)h, (long long)ph);
        if (rc == RES_OK) {
            char hex[129];
            for (size_t i = 0; i < oi.assoc_len && i < 64; i++)
                snprintf(hex + 2 * i, 3, "%02x", oi.assoc[i]);
            hex[2 * (oi.assoc_len < 64 ? oi.assoc_len : 64)] = 0;
            bn += snprintf(body + bn, sizeof body - bn,
                           ",\"addr\":\"%s\",\"port\":%d,\"tlsa\":[{\"usage\":%u,"
                           "\"selector\":%u,\"mtype\":%u,\"data\":\"%s\"}]",
                           oi.host, oi.port, oi.usage, oi.selector, oi.mtype, hex);
        }
        bn += snprintf(body + bn, sizeof body - bn, "}");
    }
    char hd[256];
    int hn = snprintf(hd, sizeof hd,
                      "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                      "Cache-Control: no-store\r\nContent-Length: %d\r\n"
                      "Connection: close\r\n\r\n", bn);
    if (fd_write_all(cfd, hd, (size_t)hn) == 0) fd_write_all(cfd, body, (size_t)bn);
}

/* ── dane-08: read-only name queries (--dane-api only, loopback only) ──────
 * GET /gd/name?n=<label|label.tld>  → owner hash160 + state from the fold db
 * GET /gd/owned?h160=<40 hex>       → names owned by that hash160 (≤ GD_OWNED_MAX)
 * Inputs are validated before any db access; the db is opened read-only per
 * request (idx_db_open_ro) so the sync writer is never blocked or migrated. */
#define GD_OWNED_MAX   64
#define GD_BODY_MAX    4096

static void json_reply(int cfd, const char *status, const char *body, int bn) {
    char hd[256];
    int hn = snprintf(hd, sizeof hd,
                      "HTTP/1.1 %s\r\nContent-Type: application/json\r\n"
                      "Cache-Control: no-store\r\nContent-Length: %d\r\n"
                      "Connection: close\r\n\r\n", status, bn);
    if (fd_write_all(cfd, hd, (size_t)hn) == 0 && bn > 0) fd_write_all(cfd, body, (size_t)bn);
}

static int peer_is_loopback(int cfd) {
    struct sockaddr_storage ss; socklen_t sl = sizeof ss;
    if (getpeername(cfd, (struct sockaddr *)&ss, &sl) != 0) return 0;
    if (ss.ss_family == AF_INET)
        return (ntohl(((struct sockaddr_in *)&ss)->sin_addr.s_addr) >> 24) == 127;
    if (ss.ss_family == AF_INET6) {
        const struct in6_addr *a = &((struct sockaddr_in6 *)&ss)->sin6_addr;
        return IN6_IS_ADDR_LOOPBACK(a);
    }
    return 0;
}

/* copy the query value up to ' ' / '&' / CR; -1 if longer than max or empty */
static int query_val(const char *q, char *out, size_t max) {
    size_t n = 0;
    for (; q[n] && q[n] != ' ' && q[n] != '&' && q[n] != '\r' && q[n] != '\n'; n++) {
        if (n >= max) return -1;
        out[n] = q[n];
    }
    out[n] = 0;
    return n ? (int)n : -1;
}

/* protocol-spec name charset [a-z0-9-], 1..32 bytes; strips our own .tld */
static int gd_name_normalize(const char *in, char out[33]) {
    char buf[64];
    size_t n = strlen(in);
    if (n == 0 || n >= sizeof buf) return 0;
    for (size_t i = 0; i <= n; i++) buf[i] = (char)tolower((unsigned char)in[i]);
    size_t tl = strlen(g->dot_tld);
    if (tl && n > tl && !strcmp(buf + n - tl, g->dot_tld)) { n -= tl; buf[n] = 0; }
    if (n == 0 || n > 32) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = buf[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return 0;
    }
    memcpy(out, buf, n + 1);
    return 1;
}

static void name_api(int cfd, const char *q) {
    char raw[64], name[33], body[512];
    int bn;
    if (query_val(q, raw, sizeof raw - 1) < 0 || !gd_name_normalize(raw, name)) {
        bn = snprintf(body, sizeof body, "{\"status\":\"bad_name\"}");
        json_reply(cfd, "400 Bad Request", body, bn); return;
    }
    sqlite3 *db = g->chain_db[0] ? idx_db_open_ro(g->chain_db) : NULL;
    if (!db) {
        bn = snprintf(body, sizeof body, "{\"name\":\"%s\",\"status\":\"no_db\"}", name);
        json_reply(cfd, "503 Service Unavailable", body, bn); return;
    }
    char owner[41] = ""; char st = 0;
    int found = idx_db_resolve(db, name, owner, &st);
    idx_db_close(db);
    if (found)
        bn = snprintf(body, sizeof body,
                      "{\"name\":\"%s\",\"tld\":\"%s\",\"status\":\"ok\",\"owner\":\"%s\",\"state\":%d}",
                      name, g->tld, owner, (int)st);
    else
        bn = snprintf(body, sizeof body,
                      "{\"name\":\"%s\",\"tld\":\"%s\",\"status\":\"unowned\"}", name, g->tld);
    json_reply(cfd, "200 OK", body, bn);
}

typedef struct { char *b; int n, cap, count, trunc; } OwnedAcc;
static void owned_cb(void *u, const char *name, int64_t lease_expiry, int st) {
    OwnedAcc *a = u;
    if (a->trunc) return;
    char nm[33];
    /* names in the fold are already canonical; re-check so JSON stays clean */
    size_t l = name ? strlen(name) : 0;
    if (!l || l > 32) return;
    for (size_t i = 0; i < l; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return;
    }
    memcpy(nm, name, l + 1);
    if (a->count >= GD_OWNED_MAX) { a->trunc = 1; return; }
    int w = snprintf(a->b + a->n, (size_t)(a->cap - a->n),
                     "%s{\"name\":\"%s\",\"lease_expiry\":%lld,\"state\":%d}",
                     a->count ? "," : "", nm, (long long)lease_expiry, st);
    if (w < 0 || w >= a->cap - a->n - 64) { a->trunc = 1; return; }
    a->n += w; a->count++;
}

static void owned_api(int cfd, const char *q) {
    char h[48], body[GD_BODY_MAX];
    int bn;
    int hl = query_val(q, h, 41);
    int ok = hl == 40;
    for (int i = 0; ok && i < 40; i++) {
        h[i] = (char)tolower((unsigned char)h[i]);
        if (!isxdigit((unsigned char)h[i])) ok = 0;
    }
    if (!ok) {
        bn = snprintf(body, sizeof body, "{\"status\":\"bad_h160\"}");
        json_reply(cfd, "400 Bad Request", body, bn); return;
    }
    sqlite3 *db = g->chain_db[0] ? idx_db_open_ro(g->chain_db) : NULL;
    if (!db) {
        bn = snprintf(body, sizeof body, "{\"h160\":\"%s\",\"status\":\"no_db\"}", h);
        json_reply(cfd, "503 Service Unavailable", body, bn); return;
    }
    bn = snprintf(body, sizeof body, "{\"h160\":\"%s\",\"tld\":\"%s\",\"status\":\"ok\",\"names\":[", h, g->tld);
    OwnedAcc a = { body, bn, (int)sizeof body, 0, 0 };
    idx_db_owned(db, h, owned_cb, &a);
    idx_db_close(db);
    bn = a.n;
    bn += snprintf(body + bn, sizeof body - (size_t)bn, "],\"count\":%d,\"truncated\":%s}",
                   a.count, a.trunc ? "true" : "false");
    json_reply(cfd, "200 OK", body, bn);
}

/* ── dane-09: GET /gd/names?prefix=&offset=N&limit=M (Discover listing) ─────
 * Same gates as dane-08 (--dane-api only, loopback only, read-only db per
 * request). prefix: [a-z0-9-] 0..32 (empty = all names), lowercased, no TLD.
 * offset: 0..GD_NAMES_OFFSET_MAX, limit: 1..GD_NAMES_LIMIT_MAX (default 20).
 * Ordered by name (BINARY), served off the names PRIMARY KEY index. Body is
 * capped at GD_NAMES_BODY; rows past the cap set "truncated":true. */
#define GD_NAMES_LIMIT_DEF   20
#define GD_NAMES_LIMIT_MAX   100
#define GD_NAMES_OFFSET_MAX  10000000
#define GD_NAMES_BODY        20480

/* find key=value in a query string (stops at ' ' / CR). 1 found, 0 absent,
 * -1 present but too long; duplicate keys are rejected (-1). */
static int query_param(const char *q, const char *key, char *out, size_t max) {
    size_t kl = strlen(key); int found = 0;
    const char *p = q;
    while (*p && *p != ' ' && *p != '\r' && *p != '\n') {
        const char *e = p; while (*e && *e != '&' && *e != ' ' && *e != '\r' && *e != '\n') e++;
        if ((size_t)(e - p) > kl && !strncmp(p, key, kl) && p[kl] == '=') {
            if (found) return -1;
            size_t n = (size_t)(e - p) - kl - 1;
            if (n > max) return -1;
            memcpy(out, p + kl + 1, n); out[n] = 0; found = 1;
        }
        p = *e == '&' ? e + 1 : e;
    }
    return found;
}
static int parse_uint(const char *s, long long maxv, long long *out) {
    if (!*s || strlen(s) > 9) return 0;
    long long v = 0;
    for (const char *c = s; *c; c++) { if (*c < '0' || *c > '9') return 0; v = v * 10 + (*c - '0'); }
    if (v > maxv) return 0;
    *out = v; return 1;
}
static int gd_name_canonical(const char *n, size_t lo) {
    size_t l = n ? strlen(n) : 0;
    if (l < lo || l > 32) return 0;
    for (size_t i = 0; i < l; i++) {
        char c = n[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return 0;
    }
    return 1;
}

typedef struct { char *b; int n, cap, count, trunc; } NamesAcc;
static void names_cb(void *u, const char *name, const uint8_t *owner, int64_t lease, int st, uint64_t price) {
    NamesAcc *a = u;
    if (a->trunc || !gd_name_canonical(name, 1)) return;
    char oh[48];
    if (owner) {
        static const char *H = "0123456789abcdef";
        oh[0] = '"';
        for (int i = 0; i < 20; i++) { oh[1 + 2*i] = H[owner[i] >> 4]; oh[2 + 2*i] = H[owner[i] & 15]; }
        oh[41] = '"'; oh[42] = 0;
    } else strcpy(oh, "null");
    int w = snprintf(a->b + a->n, (size_t)(a->cap - a->n),
                     "%s{\"name\":\"%s\",\"owner_h160\":%s,\"lease_expiry\":%lld,\"state\":%d,\"price\":%llu}",
                     a->count ? "," : "", name, oh, (long long)lease, st, (unsigned long long)price);
    if (w < 0 || w >= a->cap - a->n - 96) { a->b[a->n] = 0; a->trunc = 1; return; }
    a->n += w; a->count++;
}

static pthread_mutex_t g_names_mu = PTHREAD_MUTEX_INITIALIZER;
static void names_api(int cfd, const char *q) {
    static char body[GD_NAMES_BODY];      /* off-stack; guarded by g_names_mu */
    char pfx[40], v[16];
    long long off = 0, lim = GD_NAMES_LIMIT_DEF;
    int bn, r;
    const char *err = NULL;
    pfx[0] = 0;
    r = query_param(q, "prefix", pfx, 33);
    if (r < 0) err = "bad_prefix";
    else {
        for (char *c = pfx; *c; c++) *c = (char)tolower((unsigned char)*c);
        if (pfx[0] && !gd_name_canonical(pfx, 1)) err = "bad_prefix";
    }
    if (!err && (r = query_param(q, "offset", v, 10)) != 0)
        if (r < 0 || !parse_uint(v, GD_NAMES_OFFSET_MAX, &off)) err = "bad_offset";
    if (!err && (r = query_param(q, "limit", v, 10)) != 0)
        if (r < 0 || !parse_uint(v, GD_NAMES_LIMIT_MAX, &lim) || lim < 1) err = "bad_limit";
    char small[96];
    if (err) {
        bn = snprintf(small, sizeof small, "{\"status\":\"%s\"}", err);
        json_reply(cfd, "400 Bad Request", small, bn); return;
    }
    sqlite3 *db = g->chain_db[0] ? idx_db_open_ro(g->chain_db) : NULL;
    if (!db) {
        bn = snprintf(small, sizeof small, "{\"status\":\"no_db\"}");
        json_reply(cfd, "503 Service Unavailable", small, bn); return;
    }
    pthread_mutex_lock(&g_names_mu);
    bn = snprintf(body, sizeof body, "{\"tld\":\"%s\",\"status\":\"ok\",\"prefix\":\"%s\",\"names\":[", g->tld, pfx);
    NamesAcc a = { body, bn, (int)sizeof body, 0, 0 };
    long long total = idx_db_names(db, pfx, off, (int)lim, names_cb, &a);
    idx_db_close(db);
    if (total < 0) {
        pthread_mutex_unlock(&g_names_mu);
        bn = snprintf(small, sizeof small, "{\"status\":\"db_error\"}");
        json_reply(cfd, "503 Service Unavailable", small, bn); return;
    }
    bn = a.n;
    bn += snprintf(body + bn, sizeof body - (size_t)bn,
                   "],\"total\":%lld,\"offset\":%lld,\"limit\":%lld,\"count\":%d,\"truncated\":%s}",
                   total, off, lim, a.count, a.trunc ? "true" : "false");
    json_reply(cfd, "200 OK", body, bn);
    pthread_mutex_unlock(&g_names_mu);
}

// one front-door connection: a PAC fetch, a plain-http bounce, or a CONNECT
static void pac_conn(int cfd) {
    nosigpipe(cfd);
    struct timeval tv = { 5, 0 };               // a stalled head, not a tunnel
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    char head[8192];
    int n = http_head_read(cfd, head, sizeof head);
    if (n <= 0) return;

    if (!strncmp(head, "GET /proxy.pac", 14) &&
        (head[14] == ' ' || head[14] == '?' || head[14] == '\r')) {
        pac_send(cfd); return;
    }

    if (g->passthrough && !strncmp(head, "GET /gd/tlsa?host=", 18)) {
        tlsa_api(cfd, head + 18); return;
    }
    if (g->passthrough && (!strncmp(head, "GET /gd/name?", 13) ||
                           !strncmp(head, "GET /gd/owned?", 14) ||
                           !strncmp(head, "GET /gd/names", 13))) {
        if (!peer_is_loopback(cfd)) { http_status(cfd, "403 Forbidden"); return; }
        if (!strncmp(head, "GET /gd/name?n=", 15))           name_api(cfd, head + 15);
        else if (!strncmp(head, "GET /gd/owned?h160=", 19))  owned_api(cfd, head + 19);
        else if (!strncmp(head, "GET /gd/names?", 14))       names_api(cfd, head + 14);
        else if (!strncmp(head, "GET /gd/names ", 14))       names_api(cfd, "");
        else http_status(cfd, "400 Bad Request");
        return;
    }

    if (!strncmp(head, "CONNECT ", 8)) {
        char target[300] = "";
        if (sscanf(head + 8, "%299s", target) != 1) { http_status(cfd, "400 Bad Request"); return; }
        char *colon = strrchr(target, ':');
        if (colon) *colon = 0;
        int dane_port = 0;
        if (!proxy_for_host(target, &dane_port)) {  // our TLDs only — not an open proxy
            http_status(cfd, "403 Forbidden");
            return;
        }
        int ofd;
        if (g->passthrough) {               // M3: raw TCP to the chain origin
            OriginInfo oi;
            memset(&oi, 0, sizeof oi);
            int rc = g->rv ? resolver_lookup(target, &oi, g->rv) : RES_BAD_NAME;
            if (rc != RES_OK) { http_status(cfd, "404 Not Found"); return; }
            ofd = dial_origin(oi.host, oi.port);
        } else {
            ofd = dial_loopback(dane_port);
        }
        if (ofd < 0) { http_status(cfd, "502 Bad Gateway"); return; }
        static const char est[] = "HTTP/1.1 200 Connection established\r\n\r\n";
        if (fd_write_all(cfd, est, sizeof est - 1) != 0) { close(ofd); return; }
        char *rest = strstr(head, "\r\n\r\n") + 4;   // bytes pipelined past the head
        int rn = n - (int)(rest - head);
        if (rn > 0 && fd_write_all(ofd, rest, (size_t)rn) != 0) { close(ofd); return; }
        struct timeval z = { 0, 0 };            // tunnels idle; select paces us now
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &z, sizeof z);
        splice_raw(cfd, ofd);
        close(ofd);
        return;
    }

    if (!strncmp(head, "GET http://", 11)) {    // PAC sends plain http here too
        char loc[300] = "";
        sscanf(head + 11, "%299s", loc);        // host[:port]/path — %s admits no CR/LF
        char host[300];
        snprintf(host, sizeof host, "%s", loc);
        host[strcspn(host, ":/")] = 0;
        if (proxy_for_host(host, NULL)) {
            char resp[400];
            int rn = snprintf(resp, sizeof resp,
                              "HTTP/1.1 301 Moved Permanently\r\nLocation: https://%s\r\n"
                              "Content-Length: 0\r\nConnection: close\r\n\r\n", loc);
            fd_write_all(cfd, resp, (size_t)rn);
            return;
        }
    }
    http_status(cfd, "400 Bad Request");
}

static void *pac_conn_main(void *arg) {
    int cfd = (int)(intptr_t)arg;
    pac_conn(cfd);
    close(cfd);
    __sync_fetch_and_sub(&g_pac_live, 1);
    return NULL;
}

static void *pacd_main(void *arg) {
    (void)arg;
#ifdef _WIN32
    int tick = 0;
#endif
    while (!g->stop) {                           // proxy_serve_ctl's stop rhythm
        struct pollfd pfd = { g->lfdpac, POLLIN, 0 };
#ifdef _WIN32
        // :443 comes back when its squatter (IIS, another proxy, a dev server)
        // exits — retry every ~30 s so the padlock path heals without an app
        // restart. The PAC route serves browsers either way.
        if (++tick >= 60 && g->lfd443 < 0) {
            tick = 0;
            int fd = proxy_listen("127.0.0.1", 443);
            if (fd >= 0) {
                g->lfd443 = fd;
                g->running443 = 1;
                if (pthread_create(&g->th443, NULL, proxy443_main, NULL) != 0) {
                    g->running443 = 0; close(fd); g->lfd443 = -1;
                } else
                    fprintf(stderr, "webproxy: 127.0.0.1:443 freed up — direct browser path on\n");
            }
        }
#endif
        if (poll(&pfd, 1, 500) <= 0) continue;
        int cfd = accept(g->lfdpac, NULL, NULL);
        if (cfd < 0) continue;
        if (__sync_add_and_fetch(&g_pac_live, 1) > PAC_CONN_MAX) {
            __sync_fetch_and_sub(&g_pac_live, 1);
            http_status(cfd, "503 Service Unavailable");
            close(cfd);
            continue;
        }
        pthread_t t;
        if (pthread_create(&t, NULL, pac_conn_main, (void *)(intptr_t)cfd) != 0) {
            __sync_fetch_and_sub(&g_pac_live, 1);
            close(cfd);
            continue;
        }
        pthread_detach(t);
    }
    while (__sync_add_and_fetch(&g_pac_live, 0) > 0)
        poll(NULL, 0, 50);
    g->runningpac = 0;
    return NULL;
}

static int bound_port(int fd) {
    struct sockaddr_in a; socklen_t l = sizeof a;
    memset(&a, 0, sizeof a);
    if (getsockname(fd, (struct sockaddr *)&a, &l) != 0) return 0;
    return ntohs(a.sin_port);
}

static int webproxy_start_body(const char *store_path, const char *chain_db) {
    char ddir[600];                                   // root CA follows the data dir
    if (g->data_dir_override[0])
        ca_set_dir(g->data_dir_override);
    else
        ca_set_dir(platform_data_dir(ddir, sizeof ddir));
    ca_set_name(g->data_name[0] ? g->data_name : APP_DATA_DIR);
    if (!ca_set_tld(g->tld[0] ? g->tld : APP_TLD)) return 0;
    /* --dane-api (passthrough): the browser verifies DANE itself and the
     * node never terminates TLS, so no root is minted or loaded — no
     * pepenet-root-<tld>.{crt,key} appears under the data dir. ca_ready stays
     * 0 and serve_tls() refuses on the TLS acceptors. Normal mode: unchanged. */
    if (!g->passthrough) {
        if (!ca_root_ensure(&g->root, &g->rootkey)) {
            fprintf(stderr, "webproxy: cannot ensure the %s root\n",
                    g->dot_tld[0] ? g->dot_tld : APP_DOT_TLD);
            return 0;
        }
        g->ca_ready = 1;
    } else {
        g->root = NULL; g->rootkey = NULL; g->ca_ready = 0;
    }
    snprintf(g->chain_db, sizeof g->chain_db, "%s", chain_db ? chain_db : "");
    g->rv = resolver_open(g->tld[0] ? g->tld : APP_TLD, store_path, chain_db);
    if (!g->rv) {
        fprintf(stderr, "webproxy: cannot open resolver (store=%s)\n", store_path);
        return 0;
    }
    g->lfd = proxy_listen("127.0.0.1", g->proxy_port);
    if (g->lfd >= 0 && g->proxy_port == 0) g->proxy_port = bound_port(g->lfd);
    if (g->lfd < 0) {
        fprintf(stderr, "webproxy: cannot bind 127.0.0.1:%d (already serving?)\n", g->proxy_port);
        resolver_close(g->rv); g->rv = NULL;
        return 0;
    }
    g->stop = 0;
    g->started = g->running = 1;
    if (pthread_create(&g->th, NULL, proxy_main, NULL) != 0) {
        g->started = g->running = 0;
        close(g->lfd); g->lfd = -1;                      // nothing will ever serve it
        resolver_close(g->rv); g->rv = NULL;
        return 0;
    }
    fprintf(stderr, "webproxy: DANE proxy on 127.0.0.1:%d (%s)\n",
            g->proxy_port, g->dot_tld[0] ? g->dot_tld : APP_DOT_TLD);
#ifdef _WIN32
    // the direct browser path: Windows has no pf but also no privileged-port
    // rule, so serve :443 directly (loopback only). A busy port (IIS, another
    // proxy, a dev server) just loses this route for now — the pacd loop below
    // retries every ~30 s, and the PAC route serves browsers regardless.
    g->lfd443 = proxy_listen("127.0.0.1", 443);
    if (g->lfd443 >= 0) {
        g->running443 = 1;
        if (pthread_create(&g->th443, NULL, proxy443_main, NULL) != 0) {
            g->running443 = 0;
            close(g->lfd443);
            g->lfd443 = -1;
        } else
            fprintf(stderr, "webproxy: also on 127.0.0.1:443 (the browser path)\n");
    } else {
        g->lfd443 = -1;
        fprintf(stderr, "webproxy: 127.0.0.1:443 in use — will retry; the PAC "
                        "route still serves browsers\n");
    }
#else
    // mac pf / Linux nft rdr target. sysinstall's redirect sends loopback
    // :443 here; best-effort — without the rdr the PAC path serves browsers.
    g->lfdpf = proxy_listen("127.0.0.1", g->pf_port);
    if (g->lfdpf >= 0 && g->pf_port == 0) g->pf_port = bound_port(g->lfdpf);
    if (g->lfdpf >= 0) {
        g->runningpf = 1;
        if (pthread_create(&g->thpf, NULL, proxypf_main, NULL) != 0) {
            g->runningpf = 0;
            close(g->lfdpf);
            g->lfdpf = -1;
        } else
            fprintf(stderr, "webproxy: pf rdr target on 127.0.0.1:%d\n",
                    g->pf_port);
    } else {
        g->lfdpf = -1;
        fprintf(stderr, "webproxy: 127.0.0.1:%d unavailable — the pf :443 "
                        "route is off (PAC route unaffected)\n", g->pf_port);
    }
#endif
    // the DNS-free browser path (see the front-door block comment): PAC +
    // CONNECT — on mac the PRIMARY route (no unprivileged loopback :443, pf
    // unreliable, DoH browsers skip /etc/resolver); on Windows the VPN-proof one
    g->lfdpac = proxy_listen("127.0.0.1", g->pac_port);
    if (g->lfdpac >= 0 && g->pac_port == 0) g->pac_port = bound_port(g->lfdpac);
    if (g->lfdpac >= 0) {
        g->runningpac = 1;
        if (pthread_create(&g->thpac, NULL, pacd_main, NULL) != 0) {
            g->runningpac = 0;
            close(g->lfdpac);
            g->lfdpac = -1;
        } else
            fprintf(stderr, "webproxy: PAC front door on 127.0.0.1:%d "
                            "(/proxy.pac + CONNECT %s)\n", g->pac_port,
                    g->dot_tld[0] ? g->dot_tld : APP_DOT_TLD);
    } else {
        g->lfdpac = -1;
        fprintf(stderr, "webproxy: 127.0.0.1:%d unavailable — the PAC path is off\n",
                g->pac_port);
    }
    return 1;
}

/* GreatDANE: port 0 on an instance row = kernel-assigned (bound, then read
 * back — no pick-then-bind race). The desktop rows never carry 0. */
void webproxy_ports(int *proxy, int *pac, int *pf) {
    if (proxy) *proxy = g->lfd >= 0 ? g->proxy_port : 0;
    if (pac) *pac = g->lfdpac >= 0 ? g->pac_port : 0;
    if (pf) *pf = g->pf_port;
}

int webproxy_start(const char *store_path, const char *chain_db) {
    if (g->started) return 1;
    return webproxy_start_body(store_path, chain_db) ? 1 : 0;
}

void webproxy_set_combined(int on) { g->combined = on ? 1 : 0; }
void webproxy_set_passthrough(int on) { g->passthrough = on ? 1 : 0; }

Webproxy *webproxy_start_inst(const struct AppInstance *inst, struct Dnsnet *dns) {
    if (!inst || !dns || g->started) return NULL;
    g->proxy_port = inst->proxy_port;
    g->pac_port = inst->pac_port;
    g->pf_port = inst->pf_port;
    snprintf(g->tld, sizeof g->tld, "%s", inst->tld ? inst->tld : APP_TLD);
    snprintf(g->dot_tld, sizeof g->dot_tld, ".%s", g->tld);
    snprintf(g->data_name, sizeof g->data_name, "%s",
             inst->data_dir ? inst->data_dir : APP_DATA_DIR);
    if (app_data_base()[0])
        snprintf(g->data_dir_override, sizeof g->data_dir_override, "%s/%s",
                 app_data_base(), inst->coin);
    if (!webproxy_start_body(dnsnet_store_path(), dnsnet_chain_path())) return NULL;
    return g;
}

void webproxy_stop(void) {
    if (!g->started) return;
    g->stop = 1;
    pthread_join(g->th, NULL);
    if (g->lfd >= 0) {                    // the DANE listener: nobody else closes
        close(g->lfd);                    // it, and SO_REUSEADDR alone will NOT
        g->lfd = -1;                      // let the next start rebind it
    }
#ifdef _WIN32
    if (g->lfd443 >= 0) {
        pthread_join(g->th443, NULL);
        close(g->lfd443);
        g->lfd443 = -1;
    }
#else
    if (g->lfdpf >= 0) {
        pthread_join(g->thpf, NULL);
        close(g->lfdpf);
        g->lfdpf = -1;
    }
#endif
    if (g->lfdpac >= 0) {
        pthread_join(g->thpac, NULL);
        close(g->lfdpac);
        g->lfdpac = -1;
    }
    if (g->rv) { resolver_close(g->rv); g->rv = NULL; }
    g->started = 0;
}

void webproxy_status(WebStatus *out) {
    memset(out, 0, sizeof *out);
    out->running = g->running;
    out->port = g->proxy_port;
    out->ca_ready = g->ca_ready;
    pthread_mutex_lock(&g->mu);
    out->conns = g->conns;
    out->dane_ok = g->dane_ok;
    out->dane_fail = g->dane_fail;
    out->nmint = g->nmint;
    for (int i = 0; i < g->nmint; i++) {
        snprintf(out->mint[i].sni, sizeof out->mint[i].sni, "%s", g->mint[i].sni);
        snprintf(out->mint[i].origin, sizeof out->mint[i].origin, "%s", g->mint[i].origin);
        out->mint[i].t = g->mint[i].t;
        out->mint[i].ok = g->mint[i].ok;
    }
    pthread_mutex_unlock(&g->mu);
}

// ── origin certificate — sscert over ~/.pepenet paths ────────────────────────
#include "sscert.h"

#include <stdlib.h>

static const char *origin_path(const char *apex, const char *ext) {
    static char buf[2][700];
    static int flip;
    char *b = buf[flip ^= 1];                   // crt+key callable back to back
    char name[200];
    snprintf(name, sizeof name, "origin-%s%s.%s", apex,
             g->dot_tld[0] ? g->dot_tld : APP_DOT_TLD, ext);
    if (g->data_dir_override[0]) {
        snprintf(b, sizeof buf[0], "%s/%s", g->data_dir_override, name);
        return b;
    }
    platform_data_path(name, b, sizeof buf[0]);
    return b;
}
const char *webproxy_origin_crt(const char *apex) { return origin_path(apex, "crt"); }
const char *webproxy_origin_key(const char *apex) { return origin_path(apex, "key"); }

int webproxy_origin_probe(const char *apex, uint8_t spki[32]) {
    return sscert_spki(webproxy_origin_crt(apex), spki);
}

int webproxy_origin_ensure(const char *apex, int wildcard, uint8_t spki[32],
                           int *created) {
    char fqdn[80];
    snprintf(fqdn, sizeof fqdn, "%s%s", apex, g->dot_tld[0] ? g->dot_tld : APP_DOT_TLD);
    return sscert_ensure(fqdn, webproxy_origin_crt(apex),
                         webproxy_origin_key(apex), wildcard, spki, created);
}

int webproxy_origin_wildcard(const char *apex) {
    return sscert_wildcard(webproxy_origin_crt(apex));
}

int webproxy_origin_delete(const char *apex) {
    // both halves go — a key without its cert (or vice versa) serves nothing
    int a = unlink(webproxy_origin_crt(apex));
    int b = unlink(webproxy_origin_key(apex));
    return a == 0 || b == 0;                    // 1 if anything was removed
}
