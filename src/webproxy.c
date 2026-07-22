// webproxy.c — see webproxy.h. One thread over pepenet-tls's proxy core:
// ca_root_ensure (persists ~/.pepenet/pepenet-root-pepe.{crt,key}) →
// resolver_open (own WAL read handles on the shared dns store + chain db) →
// proxy_serve_ctl on 127.0.0.1:8443 with ProxyEvents feeding the mint ring.
#include "webproxy.h"
#include "appconf.h"
#include "platform.h"

#include "ca.h"
#include "proxy.h"
#include "resolve.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <ctype.h>
#include <stdint.h>
#endif

#define WEB_PORT APP_PROXY_PORT

static struct {
    pthread_t th;
    volatile int stop;
    int started, running, ca_ready;

    X509     *root;
    EVP_PKEY *rootkey;
    Resolver *rv;
    int       lfd;
#ifdef _WIN32
    pthread_t th443;                // browsers dial <name>:443 — no pf on
    int       lfd443, running443;   // Windows, but no privileged ports either:
                                    // bind it directly, best-effort
    pthread_t thpac;                // PAC + CONNECT front door (APP_PAC_PORT):
    int       lfdpac, runningpac;   // the browser path that needs no DNS at all
#endif

    pthread_mutex_t mu;
    int64_t conns, dane_ok, dane_fail;
    struct { char sni[64]; char origin[64]; int64_t t; int ok; } mint[WEB_MINT_LOG];
    int nmint;
} g = { .mu = PTHREAD_MUTEX_INITIALIZER, .lfd = -1 };

// ProxyEvents land on the per-connection threads — ring writes under the lock
static void ev_minted(void *u, const char *sni) {
    (void)u;
    pthread_mutex_lock(&g.mu);
    g.conns++;
    memmove(g.mint + 1, g.mint, (WEB_MINT_LOG - 1) * sizeof g.mint[0]);
    snprintf(g.mint[0].sni, sizeof g.mint[0].sni, "%s", sni);
    g.mint[0].origin[0] = 0;
    g.mint[0].t = (int64_t)time(NULL);
    g.mint[0].ok = -1;                          // verdict pending
    if (g.nmint < WEB_MINT_LOG) g.nmint++;
    pthread_mutex_unlock(&g.mu);
}

static void ev_verdict(void *u, const char *sni, int dane_ok, const char *origin) {
    (void)u;
    pthread_mutex_lock(&g.mu);
    if (dane_ok) g.dane_ok++; else g.dane_fail++;
    for (int i = 0; i < g.nmint; i++)           // stamp the matching mint row
        if (g.mint[i].ok == -1 && strcmp(g.mint[i].sni, sni) == 0) {
            g.mint[i].ok = dane_ok;
            snprintf(g.mint[i].origin, sizeof g.mint[i].origin, "%s", origin ? origin : "");
            break;
        }
    pthread_mutex_unlock(&g.mu);
}

static const ProxyEvents EV = { ev_minted, ev_verdict, NULL };

static void *proxy_main(void *arg) {
    (void)arg;
    proxy_serve_ctl(g.lfd, g.root, g.rootkey, resolver_resolve, g.rv, &EV, &g.stop);
    g.running = 0;
    return NULL;
}

#ifdef _WIN32
// second acceptor on :443 — same shared state (the per-connection threads
// already assume it is safe to share; resolve.c carries the mutexes)
static void *proxy443_main(void *arg) {
    (void)arg;
    proxy_serve_ctl(g.lfd443, g.root, g.rootkey, resolver_resolve, g.rv, &EV, &g.stop);
    g.running443 = 0;
    return NULL;
}

// ── PAC + CONNECT front door (127.0.0.1:APP_PAC_PORT) ────────────────────────
// The NRPT/:53 and :443 paths both ride the OS resolver, and DNS-leak-blocking
// VPNs (Proton, Mullvad, …) install WFP filters that drop EVERY port-53 packet
// — loopback included — so ".<tld>" stops resolving whenever the VPN is up.
// This listener takes DNS out of the loop entirely: sysinstall registers
// http://127.0.0.1:<pacport>/proxy.pac as the per-user AutoConfigURL, the PAC
// steers *.<tld> at "PROXY 127.0.0.1:<pacport>" (everything else DIRECT), and
// the browser sends CONNECT carrying the literal name. We answer 200 and
// splice the socket into the resident :8443 DANE proxy — the TLS ClientHello
// (SNI and all) flows through untouched, so minting/DANE work as on any path.
// Plain http:// requests are bounced to https (parity with the dead :80).

static int fd_write_all(int fd, const char *p, size_t n) {
    size_t done = 0;
    while (done < n) {
        ssize_t w = send(fd, p + done, n - done, 0);
        if (w <= 0) return -1;
        done += (size_t)w;
    }
    return 0;
}

// accumulate until the blank line; returns total bytes (head + any pipelined
// residue) or -1. buf is NUL-terminated; headers are ASCII so strstr is safe.
static int http_head_read(int fd, char *buf, size_t cap) {
    size_t n = 0;
    while (n < cap - 1) {
        ssize_t r = recv(fd, buf + n, cap - 1 - n, 0);
        if (r <= 0) return -1;
        n += (size_t)r;
        buf[n] = 0;
        if (strstr(buf, "\r\n\r\n")) return (int)n;
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
    static const char body[] =
        "function FindProxyForURL(url, host) {\n"
        "  if (dnsDomainIs(host, \"" APP_DOT_TLD "\"))\n"
        "    return \"PROXY 127.0.0.1:" APP_PAC_PORT_S "\";\n"
        "  return \"DIRECT\";\n"
        "}\n";
    char head[256];
    int hn = snprintf(head, sizeof head,
                      "HTTP/1.1 200 OK\r\n"
                      "Content-Type: application/x-ns-proxy-autoconfig\r\n"
                      "Content-Length: %u\r\n"
                      "Cache-Control: no-cache\r\n"
                      "Connection: close\r\n\r\n",
                      (unsigned)(sizeof body - 1));
    if (fd_write_all(fd, head, (size_t)hn) == 0)
        fd_write_all(fd, body, sizeof body - 1);
}

static int dial_loopback(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
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
        ssize_t w = send(to, buf + off, (size_t)(n - off), 0);
        if (w <= 0) return 0;
        off += w;
    }
    return 1;
}

static void splice_raw(int a, int b) {
    int mx = (a > b ? a : b) + 1;
    for (;;) {
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(a, &rf);
        FD_SET(b, &rf);
        if (select(mx, &rf, NULL, NULL, NULL) <= 0) break;
        if (FD_ISSET(a, &rf) && !pump_raw(a, b)) break;
        if (FD_ISSET(b, &rf) && !pump_raw(b, a)) break;
    }
}

// one front-door connection: a PAC fetch, a plain-http bounce, or a CONNECT
static void pac_conn(int cfd) {
    struct timeval tv = { 5, 0 };               // a stalled head, not a tunnel
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    char head[8192];
    int n = http_head_read(cfd, head, sizeof head);
    if (n <= 0) return;

    if (!strncmp(head, "GET /proxy.pac", 14)) { pac_send(cfd); return; }

    if (!strncmp(head, "CONNECT ", 8)) {
        char target[300] = "";
        if (sscanf(head + 8, "%299s", target) != 1) { http_status(cfd, "400 Bad Request"); return; }
        char *colon = strrchr(target, ':');
        if (colon) *colon = 0;
        if (!suffix_is(target, APP_DOT_TLD)) {  // our TLD only — not an open proxy
            http_status(cfd, "403 Forbidden");
            return;
        }
        int ofd = dial_loopback(APP_PROXY_PORT);
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
        if (suffix_is(host, APP_DOT_TLD)) {
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
    return NULL;
}

static void *pacd_main(void *arg) {
    (void)arg;
    while (!g.stop) {                           // proxy_serve_ctl's stop rhythm
        struct pollfd pfd = { g.lfdpac, POLLIN, 0 };
        if (poll(&pfd, 1, 500) <= 0) continue;
        int cfd = accept(g.lfdpac, NULL, NULL);
        if (cfd < 0) continue;
        pthread_t t;
        if (pthread_create(&t, NULL, pac_conn_main, (void *)(intptr_t)cfd) != 0) {
            close(cfd);
            continue;
        }
        pthread_detach(t);
    }
    g.runningpac = 0;
    return NULL;
}
#endif

int webproxy_start(const char *store_path, const char *chain_db) {
    if (g.started) return 1;
    char ddir[600];                                   // root CA follows the data dir
    ca_set_dir(platform_data_dir(ddir, sizeof ddir));
    ca_set_name(APP_DATA_DIR);                         // cert files: <APP_DATA_DIR>-root-<tld>
    if (!ca_set_tld(APP_TLD)) return 0;
    if (!ca_root_ensure(&g.root, &g.rootkey)) {
        fprintf(stderr, "webproxy: cannot ensure the " APP_DOT_TLD " root\n");
        return 0;
    }
    g.ca_ready = 1;
    g.rv = resolver_open(APP_TLD, store_path, chain_db);
    if (!g.rv) {
        fprintf(stderr, "webproxy: cannot open resolver (store=%s)\n", store_path);
        return 0;
    }
    g.lfd = proxy_listen("127.0.0.1", WEB_PORT);
    if (g.lfd < 0) {
        fprintf(stderr, "webproxy: cannot bind 127.0.0.1:%d (already serving?)\n", WEB_PORT);
        resolver_close(g.rv); g.rv = NULL;
        return 0;
    }
    g.stop = 0;
    g.started = g.running = 1;
    if (pthread_create(&g.th, NULL, proxy_main, NULL) != 0) {
        g.started = g.running = 0;
        return 0;
    }
    fprintf(stderr, "webproxy: DANE proxy on 127.0.0.1:%d (" APP_DOT_TLD ")\n", WEB_PORT);
#ifdef _WIN32
    // the browser path: on mac pf redirects :443→:8443; Windows has no pf but
    // also no privileged-port rule, so serve :443 directly (loopback only).
    // A busy port (IIS, another proxy) just loses the padlock path — the DNS
    // tab keeps showing web install state.
    g.lfd443 = proxy_listen("127.0.0.1", 443);
    if (g.lfd443 >= 0) {
        g.running443 = 1;
        if (pthread_create(&g.th443, NULL, proxy443_main, NULL) != 0) {
            g.running443 = 0;
            g.lfd443 = -1;
        } else
            fprintf(stderr, "webproxy: also on 127.0.0.1:443 (the browser path)\n");
    } else {
        g.lfd443 = -1;
        fprintf(stderr, "webproxy: 127.0.0.1:443 unavailable — browsers cannot "
                        "reach " APP_DOT_TLD " sites until it frees up\n");
    }
    // the DNS-free browser path (see the front-door block comment): PAC +
    // CONNECT, best-effort like :443 — a busy port just loses the VPN-proof route
    g.lfdpac = proxy_listen("127.0.0.1", APP_PAC_PORT);
    if (g.lfdpac >= 0) {
        g.runningpac = 1;
        if (pthread_create(&g.thpac, NULL, pacd_main, NULL) != 0) {
            g.runningpac = 0;
            g.lfdpac = -1;
        } else
            fprintf(stderr, "webproxy: PAC front door on 127.0.0.1:%d "
                            "(/proxy.pac + CONNECT " APP_DOT_TLD ")\n", APP_PAC_PORT);
    } else {
        g.lfdpac = -1;
        fprintf(stderr, "webproxy: 127.0.0.1:%d unavailable — the PAC path is off\n",
                APP_PAC_PORT);
    }
#endif
    return 1;
}

void webproxy_stop(void) {
    if (!g.started) return;
    g.stop = 1;
    pthread_join(g.th, NULL);
#ifdef _WIN32
    if (g.lfd443 >= 0) {
        pthread_join(g.th443, NULL);
        g.lfd443 = -1;
    }
    if (g.lfdpac >= 0) {
        pthread_join(g.thpac, NULL);
        close(g.lfdpac);
        g.lfdpac = -1;
    }
#endif
    if (g.rv) { resolver_close(g.rv); g.rv = NULL; }
    g.started = 0;
}

void webproxy_status(WebStatus *out) {
    memset(out, 0, sizeof *out);
    out->running = g.running;
    out->port = WEB_PORT;
    out->ca_ready = g.ca_ready;
    pthread_mutex_lock(&g.mu);
    out->conns = g.conns;
    out->dane_ok = g.dane_ok;
    out->dane_fail = g.dane_fail;
    out->nmint = g.nmint;
    for (int i = 0; i < g.nmint; i++) {
        snprintf(out->mint[i].sni, sizeof out->mint[i].sni, "%s", g.mint[i].sni);
        snprintf(out->mint[i].origin, sizeof out->mint[i].origin, "%s", g.mint[i].origin);
        out->mint[i].t = g.mint[i].t;
        out->mint[i].ok = g.mint[i].ok;
    }
    pthread_mutex_unlock(&g.mu);
}

// ── origin certificate — sscert over ~/.pepenet paths ────────────────────────
#include "sscert.h"

#include <stdlib.h>

static const char *origin_path(const char *apex, const char *ext) {
    static char buf[2][700];
    static int flip;
    char *b = buf[flip ^= 1];                   // crt+key callable back to back
    char name[200];
    snprintf(name, sizeof name, "origin-%s" APP_DOT_TLD ".%s", apex, ext);
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
    snprintf(fqdn, sizeof fqdn, "%s" APP_DOT_TLD, apex);
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
