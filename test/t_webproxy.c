/* t_webproxy.c — unit tests for the browser front door in src/webproxy.c.
 *
 * WHAT IS REAL: src/webproxy.c is compiled into this binary UNMODIFIED and the
 * whole front door runs for real over loopback — webproxy_start/webproxy_stop,
 * the pacd_main accept loop, the per-connection pac_conn_main thread,
 * http_head_read, pac_send, suffix_is, dial_loopback and splice_raw/pump_raw.
 * Every assertion below is made against bytes that came off a real TCP socket
 * connected to 127.0.0.1:APP_PAC_PORT.
 *
 * WHAT IS STUBBED (at the bottom of this file, because linking them for real
 * drags in libssl/libcrypto, sqlite, the DANE + DNS stack and the Objective-C
 * platform layer): ca_set_tld/ca_set_dir/ca_set_name/ca_root_ensure (the root
 * CA is never touched — opaque non-NULL pointers are handed back),
 * resolver_open/close/resolve (an opaque handle), sscert_* (unused here),
 * platform_data_dir/platform_data_path (a scratch dir under /tmp), and the two
 * that matter:
 *   - proxy_listen()     : a byte-for-byte reimplementation of tls/src/proxy.c's
 *                          (socket, SO_REUSEADDR, bind, listen 64) so that
 *                          bind/rebind semantics — and therefore any port-release
 *                          bug — behave exactly as in production;
 *   - proxy_serve_ctl()  : stands in for the DANE TLS proxy on APP_PROXY_PORT
 *                          with the same stop-flag accept rhythm, serving a
 *                          plain ECHO. That makes the CONNECT splice observable
 *                          end to end without a TLS handshake.
 * No OpenSSL symbol is referenced; only its headers, for the opaque types.
 *
 * PROVEN HERE:
 *   1. /proxy.pac serves 200 + application/x-ns-proxy-autoconfig, an accurate
 *      Content-Length, syntactically plausible JS with FindProxyForURL that
 *      steers APP_DOT_TLD at "PROXY 127.0.0.1:<APP_PAC_PORT>" (the port in the
 *      body is checked against the APP_PAC_PORT the listener actually bound —
 *      a mismatch silently breaks every browser) and DIRECT otherwise.
 *   2. The request parser survives, bounded and without hanging forever, a
 *      corpus of hostile input: no CRLF, bare CRLF, byte-at-a-time arrival,
 *      a 16 KB unterminated request line, colon-less headers, duplicate Host,
 *      CONNECT with no/zero/huge/alphabetic/negative ports, 300+ char and
 *      NUL/CR/LF-bearing hostnames (request smuggling), an empty CONNECT
 *      target, unknown methods, and a raw TLS ClientHello.
 *   3. Unknown paths get a bounded status and never leak a file from disk.
 *   4. Client sockets are not leaked over hundreds of short connections.
 *
 * Binds only 127.0.0.1 and only the app's own high ports (8443/8444); if either
 * is already in use the suite prints a skip line and exits 0.
 */
#include "webproxy.h"
#include "appconf.h"
#include "platform.h"
#include "ca.h"
#include "proxy.h"
#include "resolve.h"
#include "sscert.h"

#include <dirent.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static int g_fail;
static int g_checks;
/* the port the stub :8443 DANE backend actually bound (see proxy_listen below:
 * it falls back to an ephemeral port when a foreign process owns APP_PROXY_PORT) */
static int g_backend_port = APP_PROXY_PORT;
#define CHECK(cond, name) do { \
    g_checks++; \
    if (cond) printf("ok   %s\n", name); \
    else      { printf("FAIL %s\n", name); g_fail = 1; } \
} while (0)

#define SECTION(s) printf("\n-- %s --\n", s)

/* ── tiny socket helpers ─────────────────────────────────────────────────── */

static long now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static int tcp_connect(int port) {
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

/* 1 if nothing is listening on 127.0.0.1:port right now. */
static int port_is_free(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    int ok = bind(fd, (struct sockaddr *)&sa, sizeof sa) == 0;
    close(fd);
    return ok;
}

#define RD_EOF  0    /* read until the peer closes                */
#define RD_HEAD 1    /* read until "\r\n\r\n" (tunnel stays open) */

/* Returns bytes read (>=0), or -1 on deadline expiry / overrun. *closed is set
 * when the server hung up. buf is always NUL-terminated (may hold NULs). */
static int read_resp(int fd, char *buf, size_t cap, int ms, int mode, int *closed) {
    size_t n = 0;
    long deadline = now_ms() + ms;
    if (closed) *closed = 0;
    buf[0] = 0;
    for (;;) {
        if (mode == RD_HEAD && n >= 4 && memmem(buf, n, "\r\n\r\n", 4)) return (int)n;
        long left = deadline - now_ms();
        if (left <= 0) return -1;
        struct pollfd p = { fd, POLLIN, 0 };
        int pr = poll(&p, 1, (int)(left > 250 ? 250 : left));
        if (pr < 0) { if (errno == EINTR) continue; return -1; }
        if (pr == 0) continue;
        if (n + 1 >= cap) return -1;
        ssize_t r = recv(fd, buf + n, cap - 1 - n, 0);
        /* an RST (the server closing on us with unread bytes queued) is a
         * connection termination, not a test failure — same as a FIN here */
        if (r < 0 && (errno == ECONNRESET || errno == EPIPE)) {
            if (closed) *closed = 1;
            buf[n] = 0;
            return (int)n;
        }
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) { if (closed) *closed = 1; buf[n] = 0; return (int)n; }
        n += (size_t)r;
        buf[n] = 0;
    }
}

static int status_of(const char *buf, int n) {
    if (n < 12 || memcmp(buf, "HTTP/1.", 7) != 0) return 0;
    return atoi(buf + 9);
}

static int fd_count(void) {
    DIR *d = opendir("/dev/fd");
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL)
        if (e->d_name[0] != '.') n++;
    closedir(d);
    return n;
}

/* One request/response round trip. Returns bytes read or -1. */
static int roundtrip(const char *req, size_t rlen, char *buf, size_t cap,
                     int ms, int mode, int *status, int *closed) {
    int fd = tcp_connect(APP_PAC_PORT);
    if (fd < 0) return -1;
    if (!rlen) rlen = strlen(req);
    if (rlen && send(fd, req, rlen, 0) < 0) { close(fd); return -1; }
    int n = read_resp(fd, buf, cap, ms, mode, closed);
    close(fd);
    if (status) *status = (n > 0) ? status_of(buf, n) : 0;
    return n;
}

/* ── the hostile-request corpus, run concurrently (many cases deliberately
 *    ride out the server's 5 s SO_RCVTIMEO, so serial would take minutes) ── */

typedef struct {
    const char *name;
    const char *req;
    size_t      rlen;      /* 0 => strlen(req) */
    int         want;      /* HTTP status, or 0 = "closed having sent nothing" */
    int         mode;      /* RD_EOF / RD_HEAD */
    /* results */
    int         got_status, got_n, got_closed, timed_out;
    char        buf[16384];
} Case;

static void *case_thread(void *a) {
    Case *c = a;
    size_t len = c->rlen ? c->rlen : strlen(c->req);
    int n = roundtrip(c->req, len, c->buf, sizeof c->buf, 15000, c->mode,
                      &c->got_status, &c->got_closed);
    c->got_n = n;
    c->timed_out = (n < 0);
    return NULL;
}

/* NUL-bearing and binary payloads need explicit lengths. */
static const char REQ_NUL[]  = "CONNECT foo\0bar.pepe:443 HTTP/1.1\r\nHost: x\r\n\r\n";
static const char REQ_HELLO[] = /* a real TLS 1.2 ClientHello prefix, binary */
    "\x16\x03\x01\x00\x2e\x01\x00\x00\x2a\x03\x03"
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
    "\x00\x00\x02\x00\x2f\x01\x00";

static char g_longhost_req[512];   /* CONNECT <310 a's>.pepe */
static char g_okhost_req[512];     /* CONNECT <240 a's>.pepe:443 */

static void on_alarm(int s) {
    (void)s;
    const char *m = "\nt_webproxy: FAIL — WATCHDOG: the suite hung past its "
                    "deadline (a front-door read never returned)\n";
    ssize_t ig = write(2, m, strlen(m)); (void)ig;
    _exit(1);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGALRM, on_alarm);
    alarm(180);                     /* CI watchdog: a hang must fail, not wedge */
    setvbuf(stdout, NULL, _IONBF, 0);

    if (!port_is_free(APP_PAC_PORT)) {
        printf("t_webproxy: SKIP — the PAC front door's fixed port 127.0.0.1:%d "
               "is already in use (is the app running?)\n", APP_PAC_PORT);
        return 0;
    }
    if (!port_is_free(APP_PROXY_PORT)) {
        /* Somebody else (a running PepeNet) owns the DANE port. The front door
         * still comes up on APP_PAC_PORT — the stub backend just moves to an
         * ephemeral port, and the two splice tests, which need to see their own
         * bytes echoed, are skipped rather than aimed at a foreign process. */
        printf("t_webproxy: NOTE — 127.0.0.1:%d is owned by another process; the "
               "stub :8443 backend moves to an ephemeral port and the CONNECT "
               "splice/echo checks are skipped.\n", APP_PROXY_PORT);
    }

    int fd0 = fd_count();

    if (!webproxy_start("/dev/null", "/dev/null")) {
        printf("FAIL webproxy_start\n");
        return 1;
    }
    /* let pacd_main reach its poll() */
    for (int i = 0; i < 100; i++) {
        int f = tcp_connect(APP_PAC_PORT);
        if (f >= 0) { close(f); break; }
        usleep(20000);
    }

    /* ── 1. PAC content ──────────────────────────────────────────────────── */
    SECTION("PAC content");

    char pac[8192];
    int  st = 0, closed = 0;
    int  n = roundtrip("GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", 0,
                       pac, sizeof pac, 8000, RD_EOF, &st, &closed);
    CHECK(n > 0, "GET /proxy.pac answers");
    CHECK(st == 200, "GET /proxy.pac is 200");
    CHECK(closed == 1, "server closes the PAC connection (Connection: close)");
    CHECK(strstr(pac, "Content-Type: application/x-ns-proxy-autoconfig") != NULL,
          "Content-Type: application/x-ns-proxy-autoconfig");

    const char *body = strstr(pac, "\r\n\r\n");
    body = body ? body + 4 : "";
    size_t blen = strlen(body);
    CHECK(blen > 0, "PAC has a body");

    const char *cl = strstr(pac, "Content-Length:");
    long clv = cl ? strtol(cl + 15, NULL, 10) : -1;
    CHECK(clv == (long)blen, "Content-Length matches the actual body length");

    CHECK(strstr(body, "function FindProxyForURL(url, host)") != NULL,
          "body defines FindProxyForURL(url, host)");
    CHECK(strstr(body, "dnsDomainIs(host,") != NULL, "body calls dnsDomainIs(host, ...)");
    CHECK(strstr(body, "\"" APP_DOT_TLD "\"") != NULL, "body matches on \"" APP_DOT_TLD "\"");
    CHECK(strstr(body, "return \"DIRECT\"") != NULL, "body returns DIRECT for everything else");

    char want_proxy[64];
    snprintf(want_proxy, sizeof want_proxy, "return \"PROXY 127.0.0.1:%d\"", APP_PAC_PORT);
    CHECK(strstr(body, want_proxy) != NULL,
          "body steers " APP_DOT_TLD " at PROXY 127.0.0.1:<APP_PAC_PORT> (port matches the bound port)");
    /* the stringified twin used to build the body must equal the numeric one */
    CHECK(atoi(APP_PAC_PORT_S) == APP_PAC_PORT, "APP_PAC_PORT_S == APP_PAC_PORT");

    int brace = 0, paren = 0, quote = 0, bad = 0;
    for (const char *p = body; *p; p++) {
        if (*p == '{') brace++;
        else if (*p == '}') { if (--brace < 0) bad = 1; }
        else if (*p == '(') paren++;
        else if (*p == ')') { if (--paren < 0) bad = 1; }
        else if (*p == '"') quote++;
    }
    CHECK(!bad && brace == 0 && paren == 0 && (quote % 2) == 0,
          "PAC body is balanced JS (braces, parens, quotes)");
    CHECK(strstr(pac, "Cache-Control: no-cache") != NULL, "PAC is no-cache");
    CHECK(memchr(body, 0, blen) == NULL, "PAC body has no embedded NUL");

    char refpac[8192];
    snprintf(refpac, sizeof refpac, "%s", body);   /* reference for later */

    /* ── 2. request-parser robustness ────────────────────────────────────── */
    SECTION("request parsing robustness");

    memset(g_longhost_req, 0, sizeof g_longhost_req);
    strcpy(g_longhost_req, "CONNECT ");
    memset(g_longhost_req + 8, 'a', 310);
    strcat(g_longhost_req, ".pepe:443 HTTP/1.1\r\nHost: x\r\n\r\n");
    memset(g_okhost_req, 0, sizeof g_okhost_req);
    strcpy(g_okhost_req, "CONNECT ");
    memset(g_okhost_req + 8, 'a', 240);
    strcat(g_okhost_req, ".pepe:443 HTTP/1.1\r\n\r\n");

    Case cases[] = {
      /* name                                request                                                              rlen  want  mode */
      { "no CRLF at all: bounded close",     "GET /proxy.pac HTTP/1.1",                                            0,   0,   RD_EOF, 0,0,0,0,{0} },
      { "bare \\r\\n only: bounded close",   "\r\n",                                                               0,   0,   RD_EOF, 0,0,0,0,{0} },
      { "header with no colon still parses", "GET /proxy.pac HTTP/1.1\r\nNotAHeaderAtAll\r\n\r\n",                 0,   200, RD_EOF, 0,0,0,0,{0} },
      { "duplicated Host header",            "GET /proxy.pac HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",              0,   200, RD_EOF, 0,0,0,0,{0} },
      { "CONNECT with no port",              "CONNECT foo.pepe HTTP/1.1\r\n\r\n",                                  0,   200, RD_HEAD,0,0,0,0,{0} },
      { "CONNECT port 0",                    "CONNECT foo.pepe:0 HTTP/1.1\r\n\r\n",                                0,   200, RD_HEAD,0,0,0,0,{0} },
      { "CONNECT port 65536 (out of range)", "CONNECT foo.pepe:65536 HTTP/1.1\r\n\r\n",                            0,   200, RD_HEAD,0,0,0,0,{0} },
      { "CONNECT port \"abc\"",              "CONNECT foo.pepe:abc HTTP/1.1\r\n\r\n",                              0,   200, RD_HEAD,0,0,0,0,{0} },
      { "CONNECT negative port",             "CONNECT foo.pepe:-1 HTTP/1.1\r\n\r\n",                               0,   200, RD_HEAD,0,0,0,0,{0} },
      { "CONNECT 240-char host is accepted", g_okhost_req,                                                         0,   200, RD_HEAD,0,0,0,0,{0} },
      { "CONNECT 310-char host is refused",  g_longhost_req,                                                       0,   403, RD_EOF, 0,0,0,0,{0} },
      { "CONNECT CR/LF-smuggled host",       "CONNECT evil.example\r\nHost: victim.pepe\r\n\r\n",                  0,   403, RD_EOF, 0,0,0,0,{0} },
      { "CONNECT LF-smuggled host",          "CONNECT evil.example\nGET /proxy.pac HTTP/1.1\r\n\r\n",              0,   403, RD_EOF, 0,0,0,0,{0} },
      { "CONNECT NUL-bearing host",          REQ_NUL,                                       sizeof REQ_NUL - 1,    0,   RD_EOF, 0,0,0,0,{0} },
      { "CONNECT with empty target",         "CONNECT  HTTP/1.1\r\n\r\n",                                          0,   403, RD_EOF, 0,0,0,0,{0} },
      { "CONNECT with nothing after it",     "CONNECT \r\n\r\n",                                                   0,   400, RD_EOF, 0,0,0,0,{0} },
      { "CONNECT to a non-" APP_TLD " host", "CONNECT example.com:443 HTTP/1.1\r\n\r\n",                           0,   403, RD_EOF, 0,0,0,0,{0} },
      { "POST is refused",                   "POST /x HTTP/1.1\r\nContent-Length: 0\r\n\r\n",                      0,   400, RD_EOF, 0,0,0,0,{0} },
      { "OPTIONS is refused",                "OPTIONS * HTTP/1.1\r\n\r\n",                                         0,   400, RD_EOF, 0,0,0,0,{0} },
      { "garbage method is refused",         "\xf0\x9f\x92\xa9 / HTTP/1.1\r\n\r\n",                                0,   400, RD_EOF, 0,0,0,0,{0} },
      { "bare TLS ClientHello on PAC port",  REQ_HELLO,                                     sizeof REQ_HELLO - 1,  0,   RD_EOF, 0,0,0,0,{0} },
      { "plain http:// to " APP_DOT_TLD,     "GET http://a.pepe/x HTTP/1.1\r\n\r\n",                               0,   301, RD_EOF, 0,0,0,0,{0} },
      { "plain http:// elsewhere refused",   "GET http://example.com/ HTTP/1.1\r\n\r\n",                           0,   400, RD_EOF, 0,0,0,0,{0} },
    };
    int ncase = (int)(sizeof cases / sizeof cases[0]);
    pthread_t th[64];
    long t0 = now_ms();
    for (int i = 0; i < ncase; i++) pthread_create(&th[i], NULL, case_thread, &cases[i]);
    for (int i = 0; i < ncase; i++) pthread_join(th[i], NULL);
    printf("     (corpus of %d hostile requests ran concurrently in %ld ms)\n",
           ncase, now_ms() - t0);

    for (int i = 0; i < ncase; i++) {
        Case *c = &cases[i];
        char nm[160];
        int ok;
        if (c->want == 0)
            ok = (!c->timed_out && c->got_closed && c->got_n == 0);
        else
            ok = (!c->timed_out && c->got_status == c->want);
        snprintf(nm, sizeof nm, "%s", c->name);
        if (!ok)
            printf("     [%s] timed_out=%d n=%d status=%d closed=%d (wanted %s%d)\n",
                   c->name, c->timed_out, c->got_n, c->got_status, c->got_closed,
                   c->want ? "status " : "clean close, status ", c->want);
        CHECK(ok, nm);
    }
    /* every case must have terminated: nothing hung past the deadline */
    int hung = 0;
    for (int i = 0; i < ncase; i++) if (cases[i].timed_out) hung++;
    CHECK(hung == 0, "no hostile request hung past its 15 s deadline");

    /* no response ever contained two status lines (smuggling / desync) */
    int desync = 0;
    for (int i = 0; i < ncase; i++) {
        const char *p = cases[i].buf;
        int c1 = 0;
        while ((p = strstr(p, "HTTP/1.1 ")) != NULL) { c1++; p += 9; }
        if (c1 > 1) { desync = 1; printf("     [%s] emitted %d status lines\n", cases[i].name, c1); }
    }
    CHECK(!desync, "no request produced two responses (no smuggling/desync)");

    /* the byte-at-a-time client: a valid request split across ~50 writes */
    {
        const char *req = "GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: */*\r\n\r\n";
        int fd = tcp_connect(APP_PAC_PORT);
        CHECK(fd >= 0, "byte-at-a-time: connect");
        for (const char *p = req; fd >= 0 && *p; p++) {
            if (send(fd, p, 1, 0) != 1) break;
            usleep(1000);
        }
        char b[8192];
        int m = fd >= 0 ? read_resp(fd, b, sizeof b, 8000, RD_EOF, &closed) : -1;
        if (fd >= 0) close(fd);
        const char *bb = m > 0 ? strstr(b, "\r\n\r\n") : NULL;
        CHECK(m > 0 && status_of(b, m) == 200, "byte-at-a-time request still yields 200");
        CHECK(bb && strcmp(bb + 4, refpac) == 0,
              "byte-at-a-time body is byte-identical to the reference PAC");
    }

    /* the 16 KB unterminated request line: must be bounded, never overrun */
    {
        char big[16 * 1024 + 64];
        memcpy(big, "GET /", 5);
        memset(big + 5, 'A', sizeof big - 5);
        int fd = tcp_connect(APP_PAC_PORT);
        CHECK(fd >= 0, "16 KB request line: connect");
        long sent = 0;
        while (fd >= 0 && sent < (long)sizeof big) {
            ssize_t w = send(fd, big + sent, sizeof big - (size_t)sent, 0);
            if (w <= 0) break;              /* server bailed early: fine */
            sent += w;
        }
        char b[4096];
        int m = fd >= 0 ? read_resp(fd, b, sizeof b, 10000, RD_EOF, &closed) : -1;
        if (fd >= 0) close(fd);
        CHECK(m >= 0, "16 KB unterminated request line: server terminates the connection");
        CHECK(m == 0 && closed, "16 KB unterminated request line: rejected with no body");
    }

    /* the splice: CONNECT then bytes both ways through the stub 8443 backend */
    if (g_backend_port != APP_PROXY_PORT) {
        printf("skip the CONNECT splice/echo checks — 127.0.0.1:%d is a foreign process\n",
               APP_PROXY_PORT);
    } else {
        int fd = tcp_connect(APP_PAC_PORT);
        CHECK(fd >= 0, "CONNECT splice: connect");
        const char *r = "CONNECT tunnel.pepe:443 HTTP/1.1\r\nHost: tunnel.pepe\r\n\r\n";
        send(fd, r, strlen(r), 0);
        char b[4096];
        int m = read_resp(fd, b, sizeof b, 8000, RD_HEAD, &closed);
        CHECK(m > 0 && status_of(b, m) == 200, "CONNECT " APP_DOT_TLD " is 200 Connection established");
        CHECK(m > 0 && strstr(b, "Connection established") != NULL, "CONNECT status text");
        send(fd, "PINGPING", 8, 0);
        char e[64] = {0};
        int mm = read_resp(fd, e, sizeof e, 5000, RD_HEAD, &closed);
        CHECK(mm >= 8 && memcmp(e, "PINGPING", 8) == 0,
              "bytes flow through the splice to the :8443 backend and back");
        close(fd);
    }

    /* pipelined residue: payload in the SAME write as the CONNECT head */
    if (g_backend_port == APP_PROXY_PORT) {
        int fd = tcp_connect(APP_PAC_PORT);
        const char *r = "CONNECT pipe.pepe:443 HTTP/1.1\r\n\r\nRESIDUE!";
        send(fd, r, strlen(r), 0);
        char b[4096];
        int m = read_resp(fd, b, sizeof b, 8000, RD_HEAD, &closed);
        CHECK(m > 0 && status_of(b, m) == 200, "pipelined CONNECT: 200 established");
        /* the 200 head and the echoed residue may arrive coalesced */
        char e[256] = {0};
        int have = 0;
        const char *after = memmem(b, (size_t)(m > 0 ? m : 0), "\r\n\r\n", 4);
        if (after && (int)(after + 4 - b) < m) have = 1;
        if (!have) {
            int mm = read_resp(fd, e, sizeof e, 5000, RD_HEAD, &closed);
            have = mm > 0 && memmem(e, (size_t)mm, "RESIDUE!", 8) != NULL;
        } else {
            have = memmem(b, (size_t)m, "RESIDUE!", 8) != NULL;
        }
        CHECK(have, "bytes pipelined past the CONNECT head are forwarded, not dropped");
        close(fd);
    }

    /* the server is still healthy after the whole corpus */
    {
        char b[8192];
        int m = roundtrip("GET /proxy.pac HTTP/1.1\r\n\r\n", 0, b, sizeof b, 8000,
                          RD_EOF, &st, &closed);
        const char *bb = m > 0 ? strstr(b, "\r\n\r\n") : NULL;
        CHECK(m > 0 && st == 200 && bb && strcmp(bb + 4, refpac) == 0,
              "front door still serves an identical PAC after the hostile corpus");
    }

    /* ── 3. paths ────────────────────────────────────────────────────────── */
    SECTION("path handling / no traversal");
    struct { const char *req; const char *name; const char *nodisk; int want; } paths[] = {
        { "GET / HTTP/1.1\r\n\r\n",                          "GET / is refused",
          "  ...GET / serves nothing from disk",                                   400 },
        { "GET /index.html HTTP/1.1\r\n\r\n",                "GET /index.html is refused",
          "  ...GET /index.html serves nothing from disk",                         400 },
        { "GET /../../etc/passwd HTTP/1.1\r\n\r\n",          "GET /../../etc/passwd is refused",
          "  ...GET /../../etc/passwd serves nothing from disk",                   400 },
        { "GET /etc/passwd HTTP/1.1\r\n\r\n",                "GET /etc/passwd is refused",
          "  ...GET /etc/passwd serves nothing from disk",                         400 },
        { "GET /..%2f..%2fetc%2fpasswd HTTP/1.1\r\n\r\n",    "encoded traversal is refused",
          "  ...encoded traversal serves nothing from disk",                       400 },
        { "GET /proxy.pac/../../etc/passwd HTTP/1.1\r\n\r\n","traversal under /proxy.pac answers 200",
          "  ...and it is the PAC verbatim, never a disk file",                    200 },
        { "GET /proxy.pac/x HTTP/1.1\r\n\r\n",               "GET /proxy.pac/x answers 200 (prefix match)",
          "  ...and it is the PAC verbatim, never a disk file",                    200 },
    };
    for (size_t i = 0; i < sizeof paths / sizeof paths[0]; i++) {
        char b[8192];
        int m = roundtrip(paths[i].req, 0, b, sizeof b, 8000, RD_EOF, &st, &closed);
        CHECK(m >= 0 && st == paths[i].want, paths[i].name);
        const char *bb = m > 0 ? strstr(b, "\r\n\r\n") : NULL;
        int leaked = 0;
        if (bb) {
            if (strstr(bb + 4, "root:")) leaked = 1;
            if (strstr(bb + 4, "/bin/")) leaked = 1;
            if (paths[i].want == 200 && strcmp(bb + 4, refpac) != 0) leaked = 1;
            if (paths[i].want == 400 && bb[4] != 0) leaked = 1;
        } else leaked = 1;
        CHECK(!leaked, paths[i].nodisk);
    }

    /* ── 4. fd hygiene ───────────────────────────────────────────────────── */
    SECTION("fd hygiene");
    {
        char b[8192];
        for (int i = 0; i < 20; i++) roundtrip("GET /proxy.pac HTTP/1.1\r\n\r\n", 0,
                                               b, sizeof b, 8000, RD_EOF, &st, &closed);
        usleep(200000);
        int before = fd_count();
        for (int i = 0; i < 300; i++) {
            int m = roundtrip("GET /proxy.pac HTTP/1.1\r\n\r\n", 0, b, sizeof b, 8000,
                              RD_EOF, &st, &closed);
            if (m <= 0 || st != 200) { printf("     PAC fetch %d failed (n=%d st=%d)\n", i, m, st); break; }
        }
        usleep(400000);
        int after = fd_count();
        printf("     open fds: %d before, %d after 300 connections\n", before, after);
        CHECK(before > 0 && after > 0, "/dev/fd is readable");
        CHECK(after <= before + 4, "300 short PAC connections leak no fds");

        /* connections that are aborted mid-head must not leak either */
        int before2 = fd_count();
        for (int i = 0; i < 200; i++) {
            int fd = tcp_connect(APP_PAC_PORT);
            if (fd < 0) continue;
            send(fd, "GET /pro", 8, 0);
            struct linger lg = { 1, 0 };            /* RST, not FIN */
            setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
            close(fd);
        }
        usleep(300000);
        int after2 = fd_count();
        printf("     open fds: %d before, %d after 200 RST aborts\n", before2, after2);
        CHECK(after2 <= before2 + 4, "200 RST-aborted connections leak no fds");
    }

    /* ── shutdown ────────────────────────────────────────────────────────── */
    SECTION("shutdown");
    webproxy_stop();
    usleep(300000);
    CHECK(port_is_free(APP_PAC_PORT), "webproxy_stop releases 127.0.0.1:" APP_PAC_PORT_S);
    /* FAILS: webproxy_stop() (src/webproxy.c:375-392) joins g.th but never
     * close()s g.lfd, so the DANE listener socket stays bound and LISTENing and
     * its fd leaks. A restart therefore cannot rebind APP_PROXY_PORT
     * (proxy_listen sets SO_REUSEADDR only, which does not permit a second live
     * listener on the same addr:port). See j_webproxy's start/stop section. */
    CHECK(port_is_free(g_backend_port),
          "webproxy_stop releases the DANE listener port (127.0.0.1:" APP_PROXY_PORT_S ")");

    int fd1 = fd_count();
    printf("     open fds: %d at start, %d after stop\n", fd0, fd1);
    /* FAILS: same root cause — the unclosed g.lfd is a permanently leaked fd. */
    CHECK(fd1 <= fd0, "start+stop leaks no fd");

    printf("\n%d checks, %s\n", g_checks, g_fail ? "SOME FAILED" : "all ok");
    printf(g_fail ? "t_webproxy: FAIL\n" : "t_webproxy: all ok\n");
    return g_fail;
}

/* ══ stubs for webproxy.c's dependencies ═══════════════════════════════════
 * See the file header: everything below stands in for a module that would drag
 * OpenSSL/sqlite/ObjC into the link. proxy_listen mirrors tls/src/proxy.c's
 * exactly; proxy_serve_ctl is a stop-flag-polling echo server on APP_PROXY_PORT.
 */
static char g_fake_root, g_fake_key, g_fake_rv;

int  ca_set_tld(const char *tld)  { (void)tld; return 1; }
const char *ca_tld(void)          { return APP_TLD; }
void ca_set_dir(const char *dir)  { (void)dir; }
void ca_set_name(const char *nm)  { (void)nm; }
int  ca_root_ensure(X509 **cert, EVP_PKEY **key) {
    *cert = (X509 *)&g_fake_root;
    *key  = (EVP_PKEY *)&g_fake_key;
    return 1;
}
int ca_leaf_mint(X509 *r, EVP_PKEY *rk, const char *n, X509 **l, EVP_PKEY **lk) {
    (void)r; (void)rk; (void)n; (void)l; (void)lk; return 0;
}
const char *ca_root_cert_path(void) { return "/dev/null"; }
const char *ca_root_key_path(void)  { return "/dev/null"; }
const char *ca_root_cn(void)        { return "stub"; }

Resolver *resolver_open(const char *suffix, const char *store, const char *idx) {
    (void)suffix; (void)store; (void)idx;
    return (Resolver *)&g_fake_rv;
}
void resolver_close(Resolver *r) { (void)r; }
int resolver_resolve(const char *sni, OriginInfo *out, void *ud) {
    (void)sni; (void)out; (void)ud; return 0;
}

int sscert_ensure(const char *f, const char *c, const char *k, int w,
                  uint8_t s[32], int *cr) {
    (void)f; (void)c; (void)k; (void)w; (void)s; if (cr) *cr = 0; return 0;
}
int sscert_spki(const char *p, uint8_t s[32])  { (void)p; (void)s; return 0; }
int sscert_wildcard(const char *p)             { (void)p; return 0; }

const char *platform_data_dir(char *out, size_t cap) {
    snprintf(out, cap, "/tmp/t_webproxy_%d", (int)getpid());
    return out;
}
const char *platform_data_path(const char *name, char *out, size_t cap) {
    snprintf(out, cap, "/tmp/t_webproxy_%d/%s", (int)getpid(), name);
    return out;
}

/* byte-for-byte tls/src/proxy.c:156 — the ONE deviation is the fallback at the
 * end, which only fires for APP_PROXY_PORT when a foreign process already owns
 * it (see the NOTE in main): the stub backend then takes an ephemeral port so
 * the front door under test still comes up. APP_PAC_PORT never falls back. */
static int bind_listen(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1 ||
        bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0 ||
        listen(fd, 64) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int g_backend_pinned;

int proxy_listen(const char *ip, int port) {
    int want = (port == APP_PROXY_PORT) ? g_backend_port : port;
    int fd = bind_listen(ip, want);
    if (fd >= 0) {
        if (port == APP_PROXY_PORT) g_backend_pinned = 1;
        return fd;
    }
    /* Only the very FIRST attempt at APP_PROXY_PORT may relocate — once the
     * backend port is pinned this behaves exactly like tls/src/proxy.c, so a
     * failure to rebind (i.e. a port the app never released) is reported, not
     * papered over. */
    if (port != APP_PROXY_PORT || g_backend_pinned) return -1;
    fd = bind_listen(ip, 0);
    if (fd < 0) return -1;
    struct sockaddr_in sa;
    socklen_t sl = sizeof sa;
    if (getsockname(fd, (struct sockaddr *)&sa, &sl) == 0)
        g_backend_port = ntohs(sa.sin_port);
    g_backend_pinned = 1;
    return fd;
}

static void *echo_thread(void *a) {
    int fd = (int)(intptr_t)a;
    char b[8192];
    for (;;) {
        ssize_t r = recv(fd, b, sizeof b, 0);
        if (r <= 0) break;
        ssize_t off = 0;
        while (off < r) {
            ssize_t w = send(fd, b + off, (size_t)(r - off), 0);
            if (w <= 0) goto done;
            off += w;
        }
    }
done:
    close(fd);
    return NULL;
}

int proxy_serve_ctl(int lfd, X509 *root, EVP_PKEY *rootkey,
                    proxy_resolver resolve, void *ud,
                    const ProxyEvents *ev, volatile int *stop) {
    (void)root; (void)rootkey; (void)resolve; (void)ud; (void)ev;
    for (;;) {
        struct pollfd p = { lfd, POLLIN, 0 };
        if (stop && *stop) break;
        if (poll(&p, 1, 200) <= 0) { if (stop && *stop) break; continue; }
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) continue;
        pthread_t t;
        if (pthread_create(&t, NULL, echo_thread, (void *)(intptr_t)cfd) != 0) close(cfd);
        else pthread_detach(t);
    }
    return 0;
}
int proxy_serve(int lfd, X509 *r, EVP_PKEY *k, proxy_resolver f, void *ud) {
    return proxy_serve_ctl(lfd, r, k, f, ud, NULL, NULL);
}
int proxy_run(const char *ip, int port, X509 *r, EVP_PKEY *k,
              proxy_resolver f, void *ud) {
    (void)ip; (void)port; (void)r; (void)k; (void)f; (void)ud; return 1;
}
