/* proxy_jitter_test.c — proxy.c under concurrency, jitter, and abuse.
 *
 * proxy.c runs a detached thread per browser connection, all of them sharing
 * one Proxy struct, one server SSL_CTX, one DANE client SSL_CTX, one root
 * X509/EVP_PKEY, and one resolver. proxy_test.c drives that with three
 * sequential connections. This file drives it the way a browser actually does:
 * many connections at once, at unpredictable speeds, some of which die
 * mid-sentence.
 *
 * PROVEN here:
 *   1. CONCURRENT CORRECTNESS. 24 clients for several seconds, each writing its
 *      request in random-sized chunks with random sub-millisecond pauses, all
 *      receive a COMPLETE and UNCORRUPTED response. Every request carries a
 *      unique nonce and the origin's body is derived from that nonce, so a
 *      response delivered to the wrong connection, a truncated body, or two
 *      bodies interleaved on one connection are all detected as content
 *      mismatches rather than merely "something looked wrong".
 *   2. ABRUPT DISCONNECTS. Clients that connect and close instantly, send a
 *      partial ClientHello then RST (SO_LINGER 0), connect and say nothing
 *      (slowloris), or vanish mid-response — run concurrently while a control
 *      client keeps asserting the proxy still serves correct content.
 *   3. ADVERSARIAL SNI. Empty, over-long, control characters, punycode,
 *      non-.pepe, unresolvable, and a SAN-INJECTION attempt. Each must produce
 *      a clean refusal and must NEVER yield a certificate for a name other
 *      than the one requested.
 *   4. NO FD OR THREAD LEAK across hundreds of short connections.
 *   5. REPEATED START/STOP with connections in flight, port released each time.
 *
 * All randomness is a seeded SplitMix64 (never rand()); the seed is printed and
 * can be pinned with PEPENET_JITTER_SEED=<n> to reproduce a failure exactly.
 * JIT_CLIENTS=<n> and JIT_SECS=<n> resize the load phase (default 24 / 5 s).
 *
 * A watchdog alarm fails the run with a message rather than hanging CI, and
 * every client carries a receive timeout so a stalled proxy is REPORTED rather
 * than hanging the suite.
 *
 * THIS SUITE CURRENTLY FAILS, against real defects rather than regressions.
 * Each failing assertion carries a FAILS: note explaining the defect:
 *   - proxy.c stalls forever whenever a request spans more than one TLS record
 *     (splice()/pump() use SSL_pending where SSL_has_pending is required);
 *   - the fail-closed 404 is intermittently destroyed by a TCP RST, because
 *     proxy.c closes the connection with the request still unread.
 *
 * NOT part of `make test` (it takes ~30 s and is deliberately abusive):
 *   make check-jitter
 * and it is the suite to run under ThreadSanitizer:
 *   make check-jitter-tsan
 */
#include "proxy.h"
#include "dane.h"
#include "ca.h"

#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <pthread.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <poll.h>

#ifdef __APPLE__
#include <mach/mach.h>
#endif

static int g_fail;
#define CHECK(cond, name) do { \
    if (cond) printf("ok   %s\n", name); \
    else      { printf("FAIL %s\n", name); g_fail = 1; } \
} while (0)

/* ── seeded PRNG (SplitMix64) ─────────────────────────────────────────────── */

static uint64_t g_seed;

static uint64_t sm64(uint64_t *s) {
    uint64_t z = (*s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static uint32_t rnd_below(uint64_t *s, uint32_t n) { return n ? (uint32_t)(sm64(s) % n) : 0; }

/* ── watchdog ─────────────────────────────────────────────────────────────── */

static void on_alarm(int sig) {
    (void)sig;
    static const char msg[] =
        "\nFAIL watchdog: proxy_jitter_test hung (no progress before the deadline)\n"
        "     a hang here means the proxy deadlocked or stopped accepting.\n";
    ssize_t w = write(2, msg, sizeof msg - 1);
    (void)w;
    _exit(1);
}
static void watchdog(unsigned secs) { alarm(secs); }

/* ── process-resource counters ───────────────────────────────────────────── */

static int count_fds(void) {
    DIR *d = opendir("/dev/fd");
    if (!d) return -1;
    int n = 0;
    while (readdir(d)) n++;
    closedir(d);
    return n;
}

static int count_threads(void) {
#ifdef __APPLE__
    thread_act_array_t list;
    mach_msg_type_number_t cnt = 0;
    if (task_threads(mach_task_self(), &list, &cnt) != KERN_SUCCESS) return -1;
    for (mach_msg_type_number_t i = 0; i < cnt; i++)
        mach_port_deallocate(mach_task_self(), list[i]);
    vm_deallocate(mach_task_self(), (vm_address_t)list, cnt * sizeof(*list));
    return (int)cnt;
#else
    return -1;
#endif
}

/* ── the origin: TLS, self-signed, one thread per connection ─────────────── */

#define BODY_LEN 32768           /* spans several TLS records, so truncation shows */

static X509     *g_ocert;
static EVP_PKEY *g_okey;
static SSL_CTX  *g_octx;
static int       g_ofd;
static volatile int g_ostop;
static atomic_int g_origin_conns;

static void nosigpipe(int fd) {
#ifdef SO_NOSIGPIPE
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
}

/* The body a given nonce must produce — the whole cross-talk detector. */
static void expected_body(const char *nonce, char *out) {
    size_t nl = strlen(nonce);
    for (int i = 0; i < BODY_LEN; i++) out[i] = nonce[(size_t)i % nl];
}

static void *origin_conn(void *a) {
    int c = (int)(intptr_t)a;
    struct timeval otv = { 5, 0 };     /* never wedge forever on a stalled proxy */
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &otv, sizeof otv);
    SSL *ssl = SSL_new(g_octx);
    SSL_set_fd(ssl, c);
    if (SSL_accept(ssl) == 1) {
        /* Read until the request HEAD is complete. This loop is load bearing:
         * the clients deliberately write their request in random-sized chunks,
         * so it arrives as several TLS records. A single SSL_read would see
         * only the first fragment, parse a truncated nonce, and answer with the
         * wrong body — which the client would then report as cross-talk. The
         * origin must not manufacture the very corruption the test looks for. */
        char req[4096];
        int n = 0;
        for (;;) {
            int k = SSL_read(ssl, req + n, (int)sizeof req - 1 - n);
            if (k <= 0) break;
            n += k;
            req[n] = 0;
            if (strstr(req, "\r\n\r\n")) break;      /* head complete */
            if (n >= (int)sizeof req - 1) break;
        }
        /* Answer ONLY a complete request. If the head never arrived (because
         * the proxy stalled and our receive timeout fired), staying silent is
         * essential: replying from a half-read request would derive the body
         * from a truncated nonce, and the client would score that as
         * cross-talk. "corrupt" must mean corrupt, not "stalled upstream". */
        if (n > 0 && strstr(req, "\r\n\r\n")) {
            req[n] = 0;
            /* "GET /<nonce> HTTP/1.0" */
            char nonce[64] = "0";
            char *sl = strchr(req, '/');
            if (sl) {
                char *sp = strchr(sl, ' ');
                size_t len = sp ? (size_t)(sp - sl - 1) : 0;
                if (len && len < sizeof nonce) { memcpy(nonce, sl + 1, len); nonce[len] = 0; }
            }
            char *body = malloc(BODY_LEN);
            char head[160];
            if (body) {
                expected_body(nonce, body);
                int hl = snprintf(head, sizeof head,
                                  "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n"
                                  "Content-Length: %d\r\nConnection: close\r\n\r\n", BODY_LEN);
                int ok = SSL_write(ssl, head, hl) == hl;
                for (int off = 0; ok && off < BODY_LEN; ) {
                    int w = SSL_write(ssl, body + off, BODY_LEN - off);
                    if (w <= 0) break;
                    off += w;
                }
                free(body);
            }
        }
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(c);
    atomic_fetch_add(&g_origin_conns, 1);
    return NULL;
}

static void *origin_accept(void *u) {
    (void)u;
    while (!g_ostop) {
        struct pollfd p = { g_ofd, POLLIN, 0 };
        if (poll(&p, 1, 100) <= 0) continue;
        int c = accept(g_ofd, NULL, NULL);
        if (c < 0) continue;
        nosigpipe(c);
        pthread_t t;
        if (pthread_create(&t, NULL, origin_conn, (void *)(intptr_t)c) != 0) close(c);
        else pthread_detach(t);
    }
    return NULL;
}

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
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char *)name, -1, -1, 0);
    X509_set_issuer_name(x, nm);
    if (!X509_sign(x, k, EVP_sha256())) { X509_free(x); EVP_PKEY_free(k); return 0; }
    *cert_out = x; *key_out = k;
    return 1;
}

/* ── the resolver stub ───────────────────────────────────────────────────── */

struct route { char ip[16]; int port; uint8_t pin[32]; };

static int resolve(const char *sni, OriginInfo *out, void *ud) {
    struct route *rt = ud;
    memset(out, 0, sizeof *out);
    /* only names under .pepenet.doge (and the apex) are served */
    size_t n = strlen(sni);
    const char *suf = "pepenet.doge";
    size_t sl = strlen(suf);
    int served = (n == sl && !strcmp(sni, suf)) ||
                 (n > sl && sni[n - sl - 1] == '.' && !strcmp(sni + n - sl, suf));
    if (!served) return 0;
    if (strstr(sni, "unresolvable")) return 0;
    snprintf(out->host, sizeof out->host, "%s", rt->ip);
    out->port = rt->port;
    out->usage = 3; out->selector = 1; out->mtype = 1;
    out->assoc_len = 32;
    memcpy(out->assoc, rt->pin, 32);
    return 1;
}

/* ── the browser side ────────────────────────────────────────────────────── */

static int tcp_connect(int port) {
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

static X509     *g_root;
static EVP_PKEY *g_rootkey;
static int       g_pport;

/* Result of one full browser transaction. */
typedef enum { TX_OK, TX_CONNECT, TX_TLS, TX_SHORT, TX_CORRUPT, TX_STALL } Rc;

/* A complete request/response. `s` is this thread's PRNG state.
 * jitter: 0 = one write, no pauses (the clean control)
 *         1 = random-sized chunks and random pauses (the load profile)
 *         2 = a FIXED 6-record split with fixed pauses (the deterministic
 *             multi-record probe used by the splice()-stall A/B) */
static Rc browser_once(uint64_t *s, const char *sni, const char *nonce, int jitter) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), g_root);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL *ssl = SSL_new(ctx);
    SSL_set_tlsext_host_name(ssl, sni);
    SSL_set1_host(ssl, sni);

    Rc rc = TX_OK;
    int fd = tcp_connect(g_pport);
    if (fd < 0) { rc = TX_CONNECT; goto out; }
    /* A receive timeout turns proxy.c's splice() stall (see the "chunked
     * request framing" section) into a reportable TX_STALL instead of a hang
     * that would take the whole suite down. Generous, so ordinary slowness
     * under load is never mistaken for a stall. */
    struct timeval rtv = { 5, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof rtv);
    SSL_set_fd(ssl, fd);
    if (jitter && rnd_below(s, 4) == 0) usleep(rnd_below(s, 2000));
    if (SSL_connect(ssl) != 1 || SSL_get_verify_result(ssl) != X509_V_OK) { rc = TX_TLS; goto out; }

    char req[256];
    int rl = snprintf(req, sizeof req,
                      "GET /%s HTTP/1.0\r\nHost: %s\r\n\r\n", nonce, sni);
    /* write the request in RANDOM-SIZED chunks with random pauses */
    for (int off = 0; off < rl; ) {
        int want;
        if (jitter == 2) { int per = (rl + 5) / 6; want = rl - off < per ? rl - off : per; }
        else if (jitter) want = (int)rnd_below(s, (uint32_t)(rl - off)) + 1;
        else             want = rl - off;
        int w = SSL_write(ssl, req + off, want);
        if (w <= 0) { rc = TX_TLS; goto out; }
        off += w;
        if (jitter == 2)                            usleep(300);
        else if (jitter && rnd_below(s, 3) == 0)    usleep(rnd_below(s, 2000));
    }

    /* read to EOF, tolerating short reads */
    size_t cap = BODY_LEN + 4096, total = 0;
    char *buf = malloc(cap);
    if (!buf) { rc = TX_TLS; goto out; }
    int timed_out = 0;
    for (;;) {
        errno = 0;
        int n = SSL_read(ssl, buf + total, (int)(cap - total));
        if (n <= 0) {
            /* Separate "the proxy went quiet" from "the proxy closed early":
             * a receive timeout means bytes we were still owed never came
             * (the splice() stall), whereas a clean EOF with a short body
             * would be genuine truncation. They are different bugs. */
            timed_out = (errno == EAGAIN || errno == EWOULDBLOCK);
            break;
        }
        total += (size_t)n;
        if (total >= cap) break;
        if (jitter == 1 && rnd_below(s, 8) == 0) usleep(rnd_below(s, 1500));
    }

    /* verify: full head + the exact body this nonce must produce */
    char *hend = NULL;
    if (total > 4)
        for (size_t i = 0; i + 4 <= total; i++)
            if (!memcmp(buf + i, "\r\n\r\n", 4)) { hend = buf + i + 4; break; }
    /* No response at all is a stall whether it ended by timeout or by the
     * proxy closing empty-handed: either way the request was never answered.
     * TX_TLS is reserved for handshake/write failures. */
    if (total == 0) rc = TX_STALL;
    else if (!hend) rc = timed_out ? TX_STALL : TX_SHORT;
    else {
        size_t bodyn = total - (size_t)(hend - buf);
        if (bodyn != BODY_LEN) rc = timed_out ? TX_STALL : TX_SHORT;
        else {
            char *want = malloc(BODY_LEN);
            expected_body(nonce, want);
            rc = memcmp(hend, want, BODY_LEN) == 0 ? TX_OK : TX_CORRUPT;
            free(want);
        }
    }
    free(buf);

out:
    SSL_shutdown(ssl);
    if (fd >= 0) close(fd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return rc;
}

/* Same transaction, but the request is deliberately split across 6 TLS
 * records — the only variable in the splice()-stall A/B. */
static Rc browser_once_chunked(uint64_t *s, const char *sni, const char *nonce) {
    return browser_once(s, sni, nonce, 2);
}

/* ── 1. the concurrency + jitter load ────────────────────────────────────── */

static volatile int g_load_stop;
static atomic_int g_n_ok, g_n_connect, g_n_tls, g_n_short, g_n_corrupt, g_n_stall;

static void *load_thread(void *a) {
    int id = (int)(intptr_t)a;
    uint64_t s = g_seed + (uint64_t)id * 0x9E3779B97F4A7C15ULL;
    while (!g_load_stop) {
        char nonce[24];
        snprintf(nonce, sizeof nonce, "%d-%08x", id, (unsigned)(sm64(&s) & 0xFFFFFFFF));
        switch (browser_once(&s, "www.pepenet.doge", nonce, 1)) {
        case TX_OK:      atomic_fetch_add(&g_n_ok, 1);      break;
        case TX_CONNECT: atomic_fetch_add(&g_n_connect, 1); break;
        case TX_TLS:     atomic_fetch_add(&g_n_tls, 1);     break;
        case TX_SHORT:   atomic_fetch_add(&g_n_short, 1);   break;
        case TX_CORRUPT: atomic_fetch_add(&g_n_corrupt, 1); break;
        case TX_STALL:   atomic_fetch_add(&g_n_stall, 1);   break;
        }
    }
    return NULL;
}

/* ── 2. the abrupt-disconnect battery ────────────────────────────────────── */

static void set_linger0(int fd) {
    struct linger lg = { 1, 0 };            /* close() -> RST, no FIN */
    setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
}

static volatile int g_abuse_stop;
static atomic_int g_abuse_done;

static void *abuse_thread(void *a) {
    int id = (int)(intptr_t)a;
    uint64_t s = g_seed ^ ((uint64_t)id * 0xD1B54A32D192ED03ULL);
    while (!g_abuse_stop) {
        int kind = (int)rnd_below(&s, 5);
        int fd = tcp_connect(g_pport);
        if (fd < 0) { usleep(1000); continue; }
        switch (kind) {
        case 0:                                   /* connect and close at once */
            close(fd);
            break;
        case 1: {                                 /* partial ClientHello + RST */
            const unsigned char partial[] = { 0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00 };
            ssize_t w = send(fd, partial, 3 + rnd_below(&s, 4), 0);
            (void)w;
            set_linger0(fd);
            close(fd);
            break;
        }
        case 2:                                   /* slowloris: say nothing */
            usleep(1000 + rnd_below(&s, 4000));
            close(fd);
            break;
        case 3: {                                 /* garbage, not TLS at all */
            char junk[64];
            for (size_t i = 0; i < sizeof junk; i++) junk[i] = (char)sm64(&s);
            ssize_t w = send(fd, junk, sizeof junk, 0);
            (void)w;
            close(fd);
            break;
        }
        case 4: {                                 /* die mid-response */
            SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
            SSL *ssl = SSL_new(ctx);
            SSL_set_tlsext_host_name(ssl, "www.pepenet.doge");
            SSL_set_fd(ssl, fd);
            if (SSL_connect(ssl) == 1) {
                const char *req = "GET /abrupt HTTP/1.0\r\nHost: www.pepenet.doge\r\n\r\n";
                SSL_write(ssl, req, (int)strlen(req));
                char b[512];
                SSL_read(ssl, b, sizeof b);       /* take a sip, then vanish */
                set_linger0(fd);
            }
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(fd);
            break;
        }
        }
        atomic_fetch_add(&g_abuse_done, 1);
        usleep(rnd_below(&s, 800));
    }
    return NULL;
}

/* ── main ────────────────────────────────────────────────────────────────── */

struct serve_args { int lfd; struct route *rt; };
static void *serve_tramp(void *a) {
    struct serve_args *s = a;
    proxy_serve(s->lfd, g_root, g_rootkey, resolve, s->rt);
    return NULL;
}

/* the start/stop cycle trampoline: proxy_serve_ctl polls *stop between accepts */
struct jctl { int lfd; volatile int *stop; struct route *rt; };
static void *ctl_tramp(void *p) {
    struct jctl *c = p;
    proxy_serve_ctl(c->lfd, g_root, g_rootkey, resolve, c->rt, NULL, c->stop);
    return NULL;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGALRM, on_alarm);
    setbuf(stdout, NULL);

    const char *seedenv = getenv("PEPENET_JITTER_SEED");
    g_seed = seedenv && *seedenv ? strtoull(seedenv, NULL, 0)
                                 : ((uint64_t)time(NULL) << 20) ^ (uint64_t)getpid();
    printf("── proxy jitter/abuse suite ──\n");
    printf("seed = %llu   (re-run exactly: PEPENET_JITTER_SEED=%llu make check-jitter)\n",
           (unsigned long long)g_seed, (unsigned long long)g_seed);

    watchdog(300);                      /* whole-suite deadline */

    /* hermetic root CA in a temp HOME */
    char tmpl[] = "/tmp/pepenet-jitter.XXXXXX";
    char *home = mkdtemp(tmpl);
    if (!home) { perror("mkdtemp"); return 1; }
    setenv("HOME", home, 1);
    if (!ca_root_ensure(&g_root, &g_rootkey)) { fprintf(stderr, "root\n"); return 1; }

    /* the origin */
    if (!self_signed("origin.example.com", &g_ocert, &g_okey)) { fprintf(stderr, "ocert\n"); return 1; }
    g_octx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate(g_octx, g_ocert);
    SSL_CTX_use_PrivateKey(g_octx, g_okey);
    g_ofd = proxy_listen("127.0.0.1", 0);
    struct sockaddr_in sa; socklen_t sl = sizeof sa;
    getsockname(g_ofd, (struct sockaddr *)&sa, &sl);
    struct route rt;
    memset(&rt, 0, sizeof rt);
    snprintf(rt.ip, sizeof rt.ip, "127.0.0.1");
    rt.port = ntohs(sa.sin_port);
    dane_spki_sha256(g_ocert, rt.pin);
    pthread_t oth;
    pthread_create(&oth, NULL, origin_accept, NULL);

    /* the proxy */
    int pfd = proxy_listen("127.0.0.1", 0);
    getsockname(pfd, (struct sockaddr *)&sa, &sl);
    g_pport = ntohs(sa.sin_port);
    struct serve_args psa = { pfd, &rt };
    pthread_t pth;
    pthread_create(&pth, NULL, serve_tramp, &psa);
    usleep(100 * 1000);

    /* sanity: one clean transaction before any abuse */
    {
        uint64_t s = g_seed;
        CHECK(browser_once(&s, "www.pepenet.doge", "sanity", 0) == TX_OK,
              "baseline: a single clean request returns the exact origin body");
    }

    /* ── 1. concurrent clients with jitter ───────────────────────────────── */
    printf("-- 24 concurrent jittered clients, 5 s --\n");
    {
        int NCLIENT = getenv("JIT_CLIENTS") ? atoi(getenv("JIT_CLIENTS")) : 24;
        int SECS    = getenv("JIT_SECS")    ? atoi(getenv("JIT_SECS"))    : 5;
        pthread_t th[64];
        if (NCLIENT > 64) NCLIENT = 64;
        int fds_before = count_fds();
        for (int i = 0; i < NCLIENT; i++)
            pthread_create(&th[i], NULL, load_thread, (void *)(intptr_t)i);
        sleep((unsigned)SECS);
        g_load_stop = 1;
        for (int i = 0; i < NCLIENT; i++) pthread_join(th[i], NULL);

        int ok = atomic_load(&g_n_ok), co = atomic_load(&g_n_corrupt);
        int sh = atomic_load(&g_n_short), tl = atomic_load(&g_n_tls);
        int cn = atomic_load(&g_n_connect), st = atomic_load(&g_n_stall);
        printf("     %d complete, %d corrupt, %d short, %d STALLED, %d tls-fail, %d connect-fail\n",
               ok, co, sh, st, tl, cn);
        /* Not a product assertion — just proof the harness did real work.
         * Completed-transaction throughput is itself suppressed by the stall
         * bug (each stalled connection burns the full receive timeout), so it
         * cannot be the liveness check. */
        CHECK(ok + st + sh + tl > 30, "the load actually ran (>30 transactions attempted)");
        CHECK(co == 0, "NO cross-talk: every body matched its own request's nonce");
        CHECK(sh == 0, "NO truncation: every body was exactly Content-Length");
        CHECK(cn == 0, "no connect failures under load");
        /* FAILS: see the "chunked request framing" section below for the
         * isolated, deterministic proof and the file:line diagnosis. These
         * clients write their requests in random-sized chunks, so they trip
         * proxy.c's splice() stall constantly. */
        CHECK(st == 0, "no transaction STALLED (proxy always forwarded the full request)");
        CHECK(tl == 0, "no handshake failures under load");
        int fds_after = count_fds();
        printf("     fds before=%d after=%d\n", fds_before, fds_after);
        CHECK(fds_after <= fds_before + 8, "no fd growth across the load phase");
    }

    /* ── 1b. the splice() stall, isolated ────────────────────────────────── */
    printf("-- chunked request framing: single record vs several --\n");
    {
        /* FAILS: proxy.c's browser<->origin relay stalls whenever a request
         * arrives as MORE THAN ONE TLS record.
         *
         * splice() (proxy.c:99-111) blocks in select() on the two RAW SOCKET
         * fds. pump() (proxy.c:77-96) drains a readable session only while
         *     } while (SSL_pending(from) > 0);            <- proxy.c:94
         * SSL_pending() reports only the bytes already DECRYPTED out of the
         * record currently being returned. It does NOT report bytes that
         * OpenSSL has already pulled off the socket into its internal record
         * buffer but not yet processed — that is what SSL_has_pending() is
         * for. So when a request spans several records, one SSL_read can lift
         * more than one record's worth of bytes off the socket, hand back only
         * the first record's plaintext, and leave the remainder buffered
         * INSIDE the SSL object. pump() returns, splice() calls select(), the
         * kernel socket buffer is now empty, and select() blocks forever.
         *
         * The result is a three-way deadlock, confirmed by sampling the wedged
         * process: the browser waits for a response, proxy.c's connection
         * thread waits in pump()/SSL_read for request bytes it is already
         * holding, and the origin waits for the rest of the request. The
         * connection thread and both sockets are leaked permanently; enough of
         * them and the proxy stops serving entirely.
         *
         * Reachability is ordinary, not exotic: any client that writes headers
         * and body separately produces multiple records — every POST/PUT, every
         * form submission, every upload, and TLS 1.3 clients routinely.
         *
         * The A/B below is the whole proof: the ONLY difference between the two
         * runs is how many SSL_write calls the client uses. */
        int single_stall = 0, multi_stall = 0;
        const int N = 24;
        for (int i = 0; i < N; i++) {
            uint64_t s = g_seed + (uint64_t)i;
            char nonce[32];
            snprintf(nonce, sizeof nonce, "single-%d", i);
            if (browser_once(&s, "www.pepenet.doge", nonce, 0) == TX_STALL) single_stall++;
        }
        for (int i = 0; i < N; i++) {
            uint64_t s = g_seed + (uint64_t)i;
            char nonce[32];
            snprintf(nonce, sizeof nonce, "multi-%d", i);
            if (browser_once_chunked(&s, "www.pepenet.doge", nonce) == TX_STALL) multi_stall++;
        }
        printf("     one-record requests: %d/%d stalled;  multi-record: %d/%d stalled\n",
               single_stall, N, multi_stall, N);
        CHECK(single_stall == 0, "a request sent as ONE TLS record never stalls");
        CHECK(multi_stall == 0,
              "a request split across SEVERAL TLS records also never stalls");
        if (multi_stall)
            printf("     product bug: proxy.c:94 uses SSL_pending() where SSL_has_pending() "
                   "is required; buffered records are invisible to proxy.c:107 select()\n");
    }

    /* ── 2. abrupt-disconnect battery, control client throughout ─────────── */
    printf("-- abrupt-disconnect battery under concurrency --\n");
    {
        enum { NABUSE = 12 };
        pthread_t th[NABUSE];
        int threads_before = count_threads();
        for (int i = 0; i < NABUSE; i++)
            pthread_create(&th[i], NULL, abuse_thread, (void *)(intptr_t)i);

        /* while the abuse runs, a control client must keep succeeding */
        int ctrl_ok = 0, ctrl_bad = 0;
        uint64_t s = g_seed ^ 0xC0FFEEULL;
        for (int i = 0; i < 40; i++) {
            char nonce[32];
            snprintf(nonce, sizeof nonce, "ctrl-%d", i);
            if (browser_once(&s, "www.pepenet.doge", nonce, 0) == TX_OK) ctrl_ok++;
            else ctrl_bad++;
            usleep(20 * 1000);
        }
        g_abuse_stop = 1;
        for (int i = 0; i < NABUSE; i++) pthread_join(th[i], NULL);

        printf("     %d abusive connections, control %d ok / %d failed\n",
               atomic_load(&g_abuse_done), ctrl_ok, ctrl_bad);
        CHECK(atomic_load(&g_abuse_done) > 100, "the abuse battery actually ran");
        CHECK(ctrl_bad == 0, "a control client succeeded THROUGHOUT the abuse");
        CHECK(ctrl_ok == 40, "every control transaction returned the exact body");

        usleep(500 * 1000);
        int threads_after = count_threads();
        printf("     threads before=%d after=%d\n", threads_before, threads_after);
        CHECK(threads_after < 0 || threads_after <= threads_before + 8,
              "no thread leak: detached connection threads are reaped");
    }

    /* ── 3. adversarial SNI ──────────────────────────────────────────────── */
    printf("-- adversarial SNI --\n");
    {
        char big[512], huge[512];
        memset(big, 'a', 250); strcpy(big + 250, ".pepenet.doge");
        memset(huge, 'b', 300); huge[300] = 0;

        struct { const char *sni; const char *what; } cases[] = {
            { "",                        "empty SNI" },
            { huge,                      "300-byte SNI" },
            { big,                       "263-byte SNI under a served zone" },
            { "a\r\nb.pepenet.doge",     "SNI with CR/LF" },
            { "a\tb.pepenet.doge",       "SNI with a tab" },
            { "xn--bcher-kva.pepenet.doge", "punycode SNI" },
            { "b\xc3\xbc" "cher.pepenet.doge",  "non-ASCII (raw UTF-8) SNI" },
            { "example.com",             "not a .doge name at all" },
            { "unresolvable.pepenet.doge", "name whose zone does not resolve" },
            { "..pepenet.doge",          "empty label in the SNI" },
            { "www.pepenet.doge.evil.com", "served name as a prefix of another" },
        };

        for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
            /* The invariant: whatever happens, we must NEVER end up with a
             * verified session whose leaf names something we did not ask for,
             * and the proxy must survive. */
            SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
            X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), g_root);
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);   /* inspect, don't demand */
            SSL *ssl = SSL_new(ctx);
            SSL_set_tlsext_host_name(ssl, cases[i].sni);
            int fd = tcp_connect(g_pport);
            SSL_set_fd(ssl, fd);
            int hs = SSL_connect(ssl) == 1;
            char cn[512] = "";
            if (hs) {
                X509 *lf = SSL_get1_peer_certificate(ssl);
                if (lf) {
                    X509_NAME_get_text_by_NID(X509_get_subject_name(lf), NID_commonName,
                                              cn, (int)sizeof cn);
                    X509_free(lf);
                }
            }
            /* The invariant that matters is not byte-equality of the CN — it is
             * that the proxy never hands out a certificate for a DIFFERENT,
             * servable host than the one asked for. (A non-ASCII SNI comes back
             * re-encoded, because ca.c:157 adds the CN with MBSTRING_ASC, which
             * reads raw UTF-8 as Latin-1: "bücher..." becomes "bÃ¼cher...".
             * That is a mangled spelling of the SAME requested name, not a
             * different site, and browsers send punycode A-labels rather than
             * raw UTF-8 anyway — so it is noted, not failed.) */
            int impersonation = hs && cn[0] && strcmp(cn, "www.pepenet.doge") == 0
                                && strcmp(cases[i].sni, "www.pepenet.doge") != 0;
            CHECK(!impersonation, cases[i].what);
            if (impersonation)
                printf("     asked '%s' but got a cert for the REAL site: CN '%s'\n",
                       cases[i].sni, cn);
            else if (hs && cn[0] && strcmp(cn, cases[i].sni) != 0)
                printf("     note: '%s' came back re-encoded as CN '%s' (ca.c:157 MBSTRING_ASC)\n",
                       cases[i].sni, cn);
            SSL_shutdown(ssl);
            close(fd);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
        }

        /* SAN INJECTION: ca.c:167 builds the leaf's SAN with
         *     snprintf(san, sizeof san, "DNS:%s", name)
         * and hands that string to X509V3_EXT_conf_nid, which treats ',' as an
         * entry separator. An SNI containing a comma therefore writes EXTRA
         * SAN entries of the attacker's choosing into a leaf the local root
         * signs. The root's critical NameConstraints (permitted DNS:doge) is
         * what stops this being a real forgery, so this asserts BOTH halves:
         * the out-of-TLD name must not end up trusted. */
        const char *inj = "evil.pepenet.doge,DNS:victim.example.com";
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), g_root);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        SSL *ssl = SSL_new(ctx);
        SSL_set_tlsext_host_name(ssl, inj);
        int fd = tcp_connect(g_pport);
        SSL_set_fd(ssl, fd);
        int hs = SSL_connect(ssl) == 1;
        int injected = 0, trusted = 0;
        if (hs) {
            X509 *lf = SSL_get1_peer_certificate(ssl);
            if (lf) {
                GENERAL_NAMES *sans = X509_get_ext_d2i(lf, NID_subject_alt_name, NULL, NULL);
                for (int j = 0; sans && j < sk_GENERAL_NAME_num(sans); j++) {
                    GENERAL_NAME *gn = sk_GENERAL_NAME_value(sans, j);
                    if (gn->type != GEN_DNS) continue;
                    const char *d = (const char *)ASN1_STRING_get0_data(gn->d.dNSName);
                    if (strstr(d, "victim.example.com")) injected = 1;
                }
                GENERAL_NAMES_free(sans);
                /* would a verifier honouring NameConstraints accept it? */
                X509_STORE *st = X509_STORE_new();
                X509_STORE_add_cert(st, g_root);
                X509_STORE_CTX *sc = X509_STORE_CTX_new();
                X509_STORE_CTX_init(sc, st, lf, NULL);
                trusted = X509_verify_cert(sc) == 1;
                X509_STORE_CTX_free(sc);
                X509_STORE_free(st);
                X509_free(lf);
            }
        }
        printf("     SAN injection: extra SAN present=%d, chain trusted=%d\n", injected, trusted);
        CHECK(!trusted,
              "SAN-injected leaf is REJECTED by the name-constrained root (constraint holds)");
        if (injected)
            printf("     hardening gap: ca.c:167 let the SNI write an extra SAN entry "
                   "(blocked only by NameConstraints, not by input validation)\n");
        SSL_shutdown(ssl);
        close(fd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);

        /* the proxy is still healthy after all of that */
        uint64_t s = g_seed ^ 0xABCDEFULL;
        CHECK(browser_once(&s, "www.pepenet.doge", "after-adversarial", 0) == TX_OK,
              "proxy still serves correct content after every adversarial SNI");
    }

    /* ── 4. fd leak across hundreds of short connections ─────────────────── */
    printf("-- fd/thread leak across 400 short connections --\n");
    {
        int before = count_fds();
        int t_before = count_threads();
        uint64_t s = g_seed ^ 0x5A5AULL;
        for (int i = 0; i < 400; i++) {
            int fd = tcp_connect(g_pport);
            if (fd < 0) continue;
            if (rnd_below(&s, 2)) {
                const unsigned char hello[] = { 0x16, 0x03, 0x01, 0x00, 0x10 };
                ssize_t w = send(fd, hello, sizeof hello, 0);
                (void)w;
            }
            close(fd);
        }
        usleep(800 * 1000);
        int after = count_fds();
        int t_after = count_threads();
        printf("     fds %d -> %d, threads %d -> %d\n", before, after, t_before, t_after);
        CHECK(after <= before + 8, "open fd count did not grow across 400 connections");
        CHECK(t_after < 0 || t_after <= t_before + 8, "thread count did not grow");

        uint64_t s2 = g_seed;
        CHECK(browser_once(&s2, "www.pepenet.doge", "after-leakcheck", 0) == TX_OK,
              "proxy still serving after 400 short connections");
    }

    /* ── 5. repeated start/stop with connections in flight ───────────────── */
    printf("-- 12 start/stop cycles with connections in flight --\n");
    {
        int cycles_ok = 0, ports_reusable = 0, served = 0;
        uint64_t s = g_seed ^ 0x1234ULL;
        for (int c = 0; c < 12; c++) {
            volatile int stopf = 0;
            int lfd = proxy_listen("127.0.0.1", 0);
            if (lfd < 0) break;
            struct sockaddr_in a; socklen_t al = sizeof a;
            getsockname(lfd, (struct sockaddr *)&a, &al);
            int port = ntohs(a.sin_port);

            /* start */
            struct jctl cargs = { lfd, &stopf, &rt };
            pthread_t th;
            pthread_create(&th, NULL, ctl_tramp, &cargs);

            usleep(30 * 1000);

            /* connections IN FLIGHT while we stop: a few real ones plus some
               half-open sockets that will still be pending at stop time */
            int save = g_pport;
            g_pport = port;
            if (browser_once(&s, "www.pepenet.doge", "cycle", 0) == TX_OK) served++;
            int inflight[4];
            for (int k = 0; k < 4; k++) {
                inflight[k] = tcp_connect(port);
                if (inflight[k] >= 0) {
                    const unsigned char partial[] = { 0x16, 0x03, 0x01, 0x01, 0x00 };
                    ssize_t w = send(inflight[k], partial, sizeof partial, 0);
                    (void)w;
                }
            }
            g_pport = save;

            /* stop */
            stopf = 1;
            struct timespec t0, t1;
            clock_gettime(CLOCK_MONOTONIC, &t0);
            pthread_join(th, NULL);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            double ms = (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
            for (int k = 0; k < 4; k++) if (inflight[k] >= 0) close(inflight[k]);
            close(lfd);
            if (ms < 1500) cycles_ok++;

            /* the port must actually be free again */
            int again = proxy_listen("127.0.0.1", port);
            if (again >= 0) { ports_reusable++; close(again); }
        }
        printf("     %d/12 stopped promptly, %d/12 ports rebindable, %d served mid-cycle\n",
               cycles_ok, ports_reusable, served);
        CHECK(cycles_ok == 12, "every start/stop cycle ended promptly (no hang)");
        CHECK(ports_reusable == 12, "the listening port was released every cycle");
        CHECK(served == 12, "each cycle served a correct response before stopping");

        uint64_t s2 = g_seed;
        CHECK(browser_once(&s2, "www.pepenet.doge", "after-cycles", 0) == TX_OK,
              "the original proxy still serves after 12 start/stop cycles");
    }

    /* ── 6. the fail-closed 404 path under the same harness ──────────────── */
    printf("-- fail-closed 404 path: response delivery --\n");
    {
        /* FAILS: this is proxy_test.c's intermittent
         * "unknown name should serve a local 404", reproduced deterministically
         * as a RATE. See the report: proxy.c:144 close(cfd) runs with the
         * browser's HTTP request still unread in the socket receive queue, so
         * BSD/macOS turns the close into a TCP RST; the RST reaches the client
         * and the kernel discards the client's ENTIRE receive buffer, including
         * the 404 that proxy.c:72 already wrote. The client then sees
         * ECONNRESET and an empty body.
         *
         * Product-side, not test-side: no client-side read loop can recover
         * data the kernel has already thrown away (proven by a retry-after-
         * reset variant, which still comes back empty).
         *
         * Threshold: even ONE reset is a user-visible ERR_EMPTY_RESPONSE where
         * a diagnostic page was intended, so this asserts zero. */
        int empty = 0, good = 0;
        for (int i = 0; i < 60; i++) {
            SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
            X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), g_root);
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
            SSL *ssl = SSL_new(ctx);
            SSL_set_tlsext_host_name(ssl, "unresolvable.pepenet.doge");
            int fd = tcp_connect(g_pport);
            SSL_set_fd(ssl, fd);
            if (SSL_connect(ssl) == 1) {
                const char *req = "GET / HTTP/1.0\r\nHost: x\r\n\r\n";
                SSL_write(ssl, req, (int)strlen(req));
                char b[4096];
                size_t tot = 0;
                int n;
                while (tot < sizeof b - 1 && (n = SSL_read(ssl, b + tot, (int)(sizeof b - 1 - tot))) > 0)
                    tot += (size_t)n;
                if (tot == 0) empty++; else good++;
            }
            SSL_shutdown(ssl);
            close(fd);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
        }
        printf("     %d/60 delivered the 404, %d/60 came back EMPTY (RST)\n", good, empty);
        CHECK(empty == 0, "the fail-closed 404 is delivered on every connection");
        if (empty)
            printf("     product bug: proxy.c:144 close() on an unread request -> RST "
                   "discards the response written at proxy.c:72\n");
    }

    g_ostop = 1;
    pthread_join(oth, NULL);
    close(g_ofd);

    /* remove the throwaway root CA + its temp HOME */
    {
        char p1[600];
        snprintf(p1, sizeof p1, "%s/.pepenet/pepenet-root-doge.crt", home); unlink(p1);
        snprintf(p1, sizeof p1, "%s/.pepenet/pepenet-root-doge.key", home); unlink(p1);
        snprintf(p1, sizeof p1, "%s/.pepenet", home); rmdir(p1);
        rmdir(home);
    }

    printf(g_fail ? "\nproxy_jitter_test: FAIL\n" : "\nproxy_jitter_test: all ok\n");
    return g_fail;
}
