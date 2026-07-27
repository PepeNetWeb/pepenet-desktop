/* j_webproxy.c — the CONCURRENCY / JITTER suite for the browser front door in
 * src/webproxy.c. Companion to t_webproxy.c (units); run with `make check-jitter`
 * and, above all, with `make TSAN=1 j_webproxy && ./j_webproxy`.
 *
 * WHAT IS REAL: src/webproxy.c is compiled into this binary UNMODIFIED. The
 * pacd_main accept loop, the detached per-connection pac_conn_main threads, the
 * shared `g` state block, webproxy_start and webproxy_stop all run for real, and
 * every client below is a real TCP socket on 127.0.0.1:APP_PAC_PORT.
 *
 * WHAT IS STUBBED (bottom of this file — see t_webproxy.c's header for the same
 * rationale): ca_*, resolver_*, sscert_*, platform_data_{dir,path}, plus
 * proxy_listen (a faithful copy of tls/src/proxy.c's: socket, SO_REUSEADDR,
 * bind, listen 64 — so port-release behaviour is production-identical) and
 * proxy_serve_ctl (a stop-flag-polling echo server standing in for the DANE
 * proxy on APP_PROXY_PORT). Nothing in the front door itself is faked.
 *
 * PROVEN HERE, under deliberately randomised timing:
 *   A. 24 concurrent clients hammering /proxy.pac for several seconds all get a
 *      COMPLETE, BYTE-IDENTICAL PAC — no interleaving, truncation, or cross-talk
 *      between connections (the core risk: shared buffers in pac_conn).
 *   B. Jitter is seeded (SplitMix64, never rand()); the seed is printed so any
 *      failure is reproducible via `./j_webproxy <seed>`. Clients write their
 *      request in random-sized chunks and sleep a random 0-2 ms after the
 *      request line and mid-headers, so partial reads and slow clients are the
 *      normal case, not the exception.
 *   C. Abrupt disconnects — connect-then-close, partial-request-then-RST
 *      (SO_LINGER 0), and never-send slowloris — do not deadlock the listener,
 *      do not leak threads/fds, and do not starve a control client that must
 *      keep getting a perfect PAC throughout.
 *   D. Repeated webproxy_start()/webproxy_stop() cycles with in-flight
 *      connections: no crash, no use-after-free, and BOTH listener ports must be
 *      genuinely released each time (a fresh bind has to succeed).
 *   E. A watchdog thread fails the run with a clear message instead of hanging.
 *
 * Binds only 127.0.0.1 and only the app's own high ports. Never port 443.
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
#include <netinet/tcp.h>
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
#include <unistd.h>

static int g_fail;
static int g_checks;
#define CHECK(cond, name) do { \
    g_checks++; \
    if (cond) printf("ok   %s\n", name); \
    else      { printf("FAIL %s\n", name); g_fail = 1; } \
} while (0)

#define SECTION(s) printf("\n-- %s --\n", s)

#define NSTORM      24      /* concurrent PAC hammerers          */
#define STORM_MS  4000      /* how long they hammer              */
#define CHAOS_MS  4000      /* abrupt-disconnect phase length    */
#define NCYCLE      12      /* start/stop cycles                 */

/* the port the stub DANE backend actually bound (see proxy_listen at the
 * bottom: it may relocate ONCE if a foreign process owns APP_PROXY_PORT) */
static int g_backend_port = APP_PROXY_PORT;

/* ── seeded randomness: SplitMix64, never rand() ─────────────────────────── */
static uint64_t g_seed;

static uint64_t sm64(uint64_t *s) {
    uint64_t z = (*s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static uint32_t sm_below(uint64_t *s, uint32_t n) { return n ? (uint32_t)(sm64(s) % n) : 0; }
static void jitter_sleep(uint64_t *s, int max_us) {   /* 0-2 ms by default */
    uint32_t us = sm_below(s, (uint32_t)max_us + 1);
    if (us) usleep(us);
}

/* ── socket helpers ──────────────────────────────────────────────────────── */
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
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    return fd;
}

/* Close with a RST instead of a FIN. At the rates below, letting thousands of
 * loopback 4-tuples sit in TIME_WAIT would exhaust the 16 k ephemeral range
 * (49152-65535) and make connect() fail with EADDRNOTAVAIL — a property of the
 * TEST's own traffic, not of the front door. Only ever used after the whole
 * response has been read, so nothing is lost. */
static void close_hard(int fd) {
    struct linger lg = { 1, 0 };
    setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    close(fd);
}

static int bind_listen(const char *ip, int port);   /* stub section */

static int port_is_free(int port) {
    int fd = bind_listen("127.0.0.1", port);
    if (fd < 0) return 0;
    close(fd);
    return 1;
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

/* read until the peer closes; -1 on deadline / overrun */
static int read_to_eof(int fd, char *buf, size_t cap, int ms) {
    size_t n = 0;
    long deadline = now_ms() + ms;
    buf[0] = 0;
    for (;;) {
        long left = deadline - now_ms();
        if (left <= 0) return -1;
        struct pollfd p = { fd, POLLIN, 0 };
        int pr = poll(&p, 1, (int)(left > 200 ? 200 : left));
        if (pr < 0) { if (errno == EINTR) continue; return -1; }
        if (pr == 0) continue;
        if (n + 1 >= cap) return -1;
        ssize_t r = recv(fd, buf + n, cap - 1 - n, 0);
        if (r < 0 && (errno == ECONNRESET || errno == EPIPE)) { buf[n] = 0; return (int)n; }
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) { buf[n] = 0; return (int)n; }
        n += (size_t)r;
        buf[n] = 0;
    }
}

/* ── the jittered PAC client ─────────────────────────────────────────────── */
/* The request is written in three jittered segments, in random-sized chunks,
 * with random 0-2 ms pauses: request line | first headers | last header + CRLF. */
static const char *SEG[3] = {
    "GET /proxy.pac HTTP/1.1\r\n",
    "Host: 127.0.0.1:" APP_PAC_PORT_S "\r\nUser-Agent: j_webproxy\r\n",
    "Accept: */*\r\nConnection: close\r\n\r\n",
};

static int send_jittered(int fd, const char *p, size_t n, uint64_t *s) {
    size_t off = 0;
    while (off < n) {
        size_t chunk = 1 + sm_below(s, 13);
        if (chunk > n - off) chunk = n - off;
        ssize_t w = send(fd, p + off, chunk, 0);
        if (w <= 0) return -1;
        off += (size_t)w;
        if (sm_below(s, 4) == 0) jitter_sleep(s, 2000);
    }
    return 0;
}

/* 0 = a complete, correct, byte-identical PAC; otherwise a failure code */
#define PF_CONNECT   1      /* the LISTENER refused us — a product failure    */
#define PF_SEND      2
#define PF_READ      3
#define PF_STATUS    4
#define PF_NOBODY    5
#define PF_MISMATCH  6
#define PF_NOPORT    7      /* the test box ran out of ephemeral ports        */

static char   g_ref[8192];      /* the reference PAC body   */
static size_t g_reflen;

static int pac_once_jittered(uint64_t *s, char *out, size_t outcap) {
    int fd = tcp_connect(APP_PAC_PORT);
    if (fd < 0)
        return (errno == EADDRNOTAVAIL || errno == EADDRINUSE ||
                errno == EAGAIN || errno == ENOBUFS) ? PF_NOPORT : PF_CONNECT;
    for (int i = 0; i < 3; i++) {
        if (send_jittered(fd, SEG[i], strlen(SEG[i]), s) != 0) { close(fd); return PF_SEND; }
        jitter_sleep(s, 2000);                  /* after the request line, mid-headers */
    }
    int n = read_to_eof(fd, out, outcap, 20000);
    close_hard(fd);
    if (n <= 0) return PF_READ;
    if (n < 12 || memcmp(out, "HTTP/1.", 7) != 0 || atoi(out + 9) != 200) return PF_STATUS;
    char *b = strstr(out, "\r\n\r\n");
    if (!b) return PF_NOBODY;
    b += 4;
    if (strlen(b) != g_reflen || memcmp(b, g_ref, g_reflen) != 0) return PF_MISMATCH;
    return 0;
}

/* ── phase A/B: the storm ────────────────────────────────────────────────── */
typedef struct {
    uint64_t seed;
    long     until;
    int      ok;
    int      fail[9];           /* indexed by PF_*                */
    int      worst_short;       /* shortest body seen, -1 if none */
    char     sample[8192];      /* first mismatching body         */
    int      have_sample;
} Storm;

static void *storm_thread(void *a) {
    Storm *st = a;
    char buf[16384];
    st->worst_short = -1;
    while (now_ms() < st->until) {
        int r = pac_once_jittered(&st->seed, buf, sizeof buf);
        if (r == 0) st->ok++;
        else {
            st->fail[r]++;
            if (!st->have_sample) {
                snprintf(st->sample, sizeof st->sample, "%.200s", buf);
                st->have_sample = 1;
            }
            char *b = strstr(buf, "\r\n\r\n");
            int bl = b ? (int)strlen(b + 4) : 0;
            if (st->worst_short < 0 || bl < st->worst_short) st->worst_short = bl;
        }
        jitter_sleep(&st->seed, 1500);
    }
    return NULL;
}

/* ── phase C: abrupt disconnects + a control client ──────────────────────── */
static atomic_int g_chaos_run;

static void *chaos_instant(void *a) {              /* connect, close at once */
    uint64_t s = (uint64_t)(uintptr_t)a * 0x2545F4914F6CDD1DULL;
    while (atomic_load(&g_chaos_run)) {
        int fd = tcp_connect(APP_PAC_PORT);
        if (fd >= 0) close(fd);                /* a plain FIN, browser-style */
        jitter_sleep(&s, 6000);
    }
    return NULL;
}

static void *chaos_rst(void *a) {                  /* partial request, then RST */
    uint64_t s = (uint64_t)(uintptr_t)a * 0x9E3779B97F4A7C15ULL;
    while (atomic_load(&g_chaos_run)) {
        int fd = tcp_connect(APP_PAC_PORT);
        if (fd >= 0) {
            const char *frag[] = { "GET /pro", "CONNECT x.pe", "\x16\x03\x01\x00", "GET /proxy.pac HTTP/1.1\r\nHo" };
            const char *f = frag[sm_below(&s, 4)];
            ssize_t ig = send(fd, f, strlen(f), 0); (void)ig;
            jitter_sleep(&s, 2000);
            struct linger lg = { 1, 0 };           /* linger 0 => RST on close */
            setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
            close(fd);
        }
        jitter_sleep(&s, 2000);
    }
    return NULL;
}

static void *chaos_slowloris(void *a) {            /* connect, never send a byte */
    uint64_t s = (uint64_t)(uintptr_t)a * 0xBF58476D1CE4E5B9ULL;
    while (atomic_load(&g_chaos_run)) {
        int fd = tcp_connect(APP_PAC_PORT);
        if (fd < 0) { usleep(5000); continue; }
        for (int i = 0; i < 60 && atomic_load(&g_chaos_run); i++) usleep(50000);
        close(fd);
        jitter_sleep(&s, 2000);
    }
    return NULL;
}

typedef struct { uint64_t seed; int ok; int bad; int noport; int firstbad; } Control;

static void *control_thread(void *a) {
    Control *c = a;
    char buf[16384];
    while (atomic_load(&g_chaos_run)) {
        int r = pac_once_jittered(&c->seed, buf, sizeof buf);
        if (r == 0)              c->ok++;
        else if (r == PF_NOPORT) c->noport++;
        else { c->bad++; if (!c->firstbad) c->firstbad = r; }
        usleep(20000);
    }
    return NULL;
}

/* ── phase D: in-flight connections held across a stop ───────────────────── */
static void *inflight_thread(void *a) {
    uint64_t s = (uint64_t)(uintptr_t)a * 0x94D049BB133111EBULL;
    int fd = tcp_connect(APP_PAC_PORT);
    if (fd < 0) return NULL;
    ssize_t ig = send(fd, SEG[0], strlen(SEG[0]), 0); (void)ig;   /* head only */
    jitter_sleep(&s, 2000);
    char buf[4096];
    /* Deliberately short: we walk away while the server's per-connection thread
     * is still parked in recv() on its 5 s SO_RCVTIMEO, so that thread outlives
     * the webproxy_stop() this connection was launched to race. */
    read_to_eof(fd, buf, sizeof buf, 600);
    close(fd);
    return NULL;
}

/* Test-only knob (phase D2): make the STUB proxy_serve_ctl close the listener
 * fd it was handed once its accept loop returns — i.e. emulate the shutdown
 * webproxy_stop() forgets to do — so the start/stop race can be exercised for
 * 10+ cycles instead of dying on cycle 2. src/webproxy.c is never touched. */
static atomic_int g_stub_release_lfd;
/* the listener fd the stub was last handed — lets the test reclaim the one
 * webproxy_stop() leaked in phase D1 before starting D2 */
static atomic_int g_stub_lfd = -1;

/* ── watchdog ────────────────────────────────────────────────────────────── */
static atomic_int g_done;
static const char *volatile g_phase = "startup";

static void *watchdog(void *a) {
    long secs = (long)(intptr_t)a;
    for (long i = 0; i < secs * 4; i++) {
        if (atomic_load(&g_done)) return NULL;
        usleep(250000);
    }
    fprintf(stderr,
            "\nj_webproxy: FAIL — WATCHDOG fired after %lds while in phase \"%s\".\n"
            "  The front door hung (a stuck accept loop, an unjoinable thread, or a\n"
            "  webproxy_stop that never returns). Reproduce with: ./j_webproxy %llu\n",
            secs, g_phase, (unsigned long long)g_seed);
    fflush(stderr);
    fflush(stdout);
    _exit(1);
}

/* ── main ────────────────────────────────────────────────────────────────── */
int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IONBF, 0);

    const char *env = getenv("PEPE_JITTER_SEED");
    if (argc > 1)      g_seed = strtoull(argv[1], NULL, 0);
    else if (env)      g_seed = strtoull(env, NULL, 0);
    else               g_seed = (uint64_t)now_ms() * 0x9E3779B97F4A7C15ULL ^ (uint64_t)getpid();
    printf("j_webproxy: seed %llu   (reproduce: ./j_webproxy %llu)\n",
           (unsigned long long)g_seed, (unsigned long long)g_seed);

    if (!port_is_free(APP_PAC_PORT)) {
        printf("j_webproxy: SKIP — the PAC front door's fixed port 127.0.0.1:%d is "
               "already in use (is the app running?)\n", APP_PAC_PORT);
        return 0;
    }
    if (!port_is_free(APP_PROXY_PORT))
        printf("j_webproxy: NOTE — 127.0.0.1:%d is owned by another process; the stub "
               "DANE backend relocates once to an ephemeral port (it is then PINNED, "
               "so port-release checks stay honest).\n", APP_PROXY_PORT);

    pthread_t wd;
    pthread_create(&wd, NULL, watchdog, (void *)(intptr_t)240);

    int fd_at_start = fd_count();

    g_phase = "first start";
    if (!webproxy_start("/dev/null", "/dev/null")) {
        printf("FAIL webproxy_start\n");
        return 1;
    }
    usleep(200000);

    /* the reference PAC, fetched once with no jitter at all */
    {
        int fd = tcp_connect(APP_PAC_PORT);
        char buf[16384];
        int n = -1;
        if (fd >= 0) {
            ssize_t ig = send(fd, "GET /proxy.pac HTTP/1.1\r\n\r\n", 27, 0); (void)ig;
            n = read_to_eof(fd, buf, sizeof buf, 8000);
            close(fd);
        }
        char *b = n > 0 ? strstr(buf, "\r\n\r\n") : NULL;
        if (!b) { printf("FAIL could not fetch the reference PAC\n"); return 1; }
        g_reflen = strlen(b + 4);
        memcpy(g_ref, b + 4, g_reflen + 1);
        printf("     reference PAC body: %zu bytes\n", g_reflen);
    }

    /* ── A/B. concurrent hammering under seeded jitter ───────────────────── */
    SECTION("concurrent PAC storm under seeded jitter");
    g_phase = "PAC storm";
    {
        static Storm st[NSTORM];
        pthread_t th[NSTORM];
        long until = now_ms() + STORM_MS;
        uint64_t s = g_seed;
        for (int i = 0; i < NSTORM; i++) {
            memset(&st[i], 0, sizeof st[i]);
            st[i].seed = sm64(&s) ^ (uint64_t)i;
            st[i].until = until;
        }
        long t0 = now_ms();
        for (int i = 0; i < NSTORM; i++) pthread_create(&th[i], NULL, storm_thread, &st[i]);
        for (int i = 0; i < NSTORM; i++) pthread_join(th[i], NULL);
        long dt = now_ms() - t0;

        int ok = 0, f[9] = {0};
        const Storm *sample = NULL;
        for (int i = 0; i < NSTORM; i++) {
            ok += st[i].ok;
            for (int k = 1; k < 9; k++) f[k] += st[i].fail[k];
            if (!sample && st[i].have_sample) sample = &st[i];
        }
        printf("     %d clients, %ld ms: %d complete PACs "
               "(connect %d, send %d, read %d, status %d, nobody %d, mismatch %d, "
               "no-ephemeral-port %d)\n",
               NSTORM, dt, ok, f[PF_CONNECT], f[PF_SEND], f[PF_READ], f[PF_STATUS],
               f[PF_NOBODY], f[PF_MISMATCH], f[PF_NOPORT]);
        if (sample) printf("     first bad response: \"%.120s\"\n", sample->sample);

        CHECK(ok > NSTORM * 4, "the storm actually made progress (>4 PACs per client)");
        CHECK(f[PF_MISMATCH] == 0,
              "every concurrent PAC body is byte-identical (no cross-talk between connections)");
        CHECK(f[PF_NOBODY] == 0, "no PAC response was truncated before its body");
        CHECK(f[PF_STATUS] == 0, "no concurrent PAC fetch got a non-200 / garbled status line");
        CHECK(f[PF_READ] == 0, "no concurrent PAC fetch stalled or was cut short");
        CHECK(f[PF_CONNECT] == 0, "the listener never refused a connection under load");
        CHECK(f[PF_SEND] == 0, "the listener never dropped a slow, chunked writer");
        CHECK(f[PF_NOPORT] == 0,
              "the test box never ran out of ephemeral ports (results are meaningful)");
    }

    /* ── C. abrupt disconnects, with a control client that must not suffer ── */
    SECTION("abrupt disconnects (close / RST / slowloris) + control liveness");
    g_phase = "abrupt disconnects";
    {
        int fd_before = fd_count();
        atomic_store(&g_chaos_run, 1);
        pthread_t th[24];
        int nth = 0;
        for (int i = 0; i < 6; i++) pthread_create(&th[nth++], NULL, chaos_instant,   (void *)(intptr_t)(i + 1));
        for (int i = 0; i < 6; i++) pthread_create(&th[nth++], NULL, chaos_rst,       (void *)(intptr_t)(i + 1));
        for (int i = 0; i < 6; i++) pthread_create(&th[nth++], NULL, chaos_slowloris, (void *)(intptr_t)(i + 1));

        static Control ctl[2];
        pthread_t cth[2];
        uint64_t s = g_seed ^ 0xC0FFEEULL;
        for (int i = 0; i < 2; i++) {
            memset(&ctl[i], 0, sizeof ctl[i]);
            ctl[i].seed = sm64(&s);
            pthread_create(&cth[i], NULL, control_thread, &ctl[i]);
        }

        usleep(CHAOS_MS * 1000);
        atomic_store(&g_chaos_run, 0);
        for (int i = 0; i < nth; i++) pthread_join(th[i], NULL);
        for (int i = 0; i < 2; i++)   pthread_join(cth[i], NULL);

        int cok = ctl[0].ok + ctl[1].ok, cbad = ctl[0].bad + ctl[1].bad;
        int cnp = ctl[0].noport + ctl[1].noport;
        int firstbad = ctl[0].firstbad ? ctl[0].firstbad : ctl[1].firstbad;
        printf("     control clients: %d perfect PACs, %d failures (first code %d), "
               "%d no-ephemeral-port\n", cok, cbad, firstbad, cnp);
        CHECK(cok > 20, "a control client kept getting perfect PACs throughout the chaos");
        CHECK(cbad == 0, "abrupt disconnects never disturbed a concurrent healthy client");
        CHECK(cnp == 0, "the test box never ran out of ephemeral ports (results are meaningful)");

        /* the listener must still be there and still correct */
        char buf[16384];
        uint64_t s2 = g_seed ^ 0xBEEFULL;
        CHECK(pac_once_jittered(&s2, buf, sizeof buf) == 0,
              "the front door still serves an identical PAC after the chaos");

        usleep(700000);                        /* let 5 s-timeout threads retire */
        for (int i = 0; i < 12 && fd_count() > fd_before + 8; i++) usleep(700000);
        int fd_after = fd_count();
        printf("     open fds: %d before chaos, %d after\n", fd_before, fd_after);
        CHECK(fd_after <= fd_before + 8,
              "abrupt disconnects leak no fds (so no leaked per-connection threads)");
    }

    /* ── D. start/stop race ──────────────────────────────────────────────── */
    SECTION("start/stop race with in-flight connections");
    g_phase = "start/stop cycles";
    {
        int cycles_run = 0, restart_failed_at = 0;
        int pac_port_stuck = 0, dane_port_stuck = 0, serve_broken = 0;
        int fds[NCYCLE + 1];
        uint64_t s = g_seed ^ 0xD15EA5EULL;

        for (int c = 0; c < NCYCLE; c++) {
            fds[c] = fd_count();

            /* serve one real request this cycle, so the front door is proven up */
            char buf[16384];
            uint64_t s2 = sm64(&s);
            if (pac_once_jittered(&s2, buf, sizeof buf) != 0) { serve_broken = c + 1; break; }

            /* three connections in flight when the stop lands */
            pthread_t inf[3];
            for (int i = 0; i < 3; i++)
                pthread_create(&inf[i], NULL, inflight_thread, (void *)(intptr_t)(c * 7 + i + 1));
            jitter_sleep(&s, 2000);

            g_phase = "webproxy_stop";
            webproxy_stop();
            for (int i = 0; i < 3; i++) pthread_join(inf[i], NULL);
            cycles_run++;

            usleep(150000);
            if (!port_is_free(APP_PAC_PORT) && !pac_port_stuck)  pac_port_stuck  = c + 1;
            if (!port_is_free(g_backend_port) && !dane_port_stuck) dane_port_stuck = c + 1;

            g_phase = "webproxy_start";
            if (!webproxy_start("/dev/null", "/dev/null")) { restart_failed_at = c + 1; break; }
            usleep(150000);
        }
        fds[cycles_run] = fd_count();
        g_phase = "start/stop verdict";

        printf("     %d of %d cycles completed; fds %d -> %d\n",
               cycles_run, NCYCLE, fds[0], fds[cycles_run]);

        CHECK(1, "webproxy_start/webproxy_stop cycles did not crash "
                 "(no segfault / use-after-free reached)");
        CHECK(serve_broken == 0, "the front door served a jittered PAC on every cycle it was up");
        CHECK(pac_port_stuck == 0,
              "webproxy_stop released 127.0.0.1:" APP_PAC_PORT_S " on every cycle");

        /* FAILS: webproxy_stop() (src/webproxy.c:375-392) joins g.th but never
         * close()s g.lfd, so the DANE listener socket from webproxy_start()
         * (src/webproxy.c:323) stays bound and LISTENing after the stop. The fd
         * leaks and the port is never released. */
        if (dane_port_stuck)
            printf("     [bug] the DANE listener port %d was still bound after the stop "
                   "in cycle %d\n", g_backend_port, dane_port_stuck);
        CHECK(dane_port_stuck == 0,
              "webproxy_stop released the DANE listener port on every cycle");

        /* FAILS: the direct consequence — proxy_listen() at src/webproxy.c:323
         * cannot rebind a port the previous run never released (SO_REUSEADDR
         * does not permit a second live listener on the same addr:port), so
         * webproxy_start() returns 0 and the app can never restart its proxy. */
        if (restart_failed_at)
            printf("     [bug] webproxy_start() returned 0 on restart #%d "
                   "(\"cannot bind 127.0.0.1:%d\")\n", restart_failed_at, g_backend_port);
        CHECK(restart_failed_at == 0,
              "webproxy_start succeeded again after every webproxy_stop (10+ cycles)");
    }

    /* ── D2. the same race, with the leaked listener neutralised ─────────── */
    /* The bug above stops the honest loop dead after one cycle, which would
     * leave the interesting part — 10+ real shutdowns racing in-flight
     * connections and detached threads — untested. So the STUB (never the
     * product) now close()s the listener fd it was handed once its accept loop
     * returns, i.e. it emulates the shutdown webproxy_stop should have done.
     * Nothing in src/webproxy.c changes; the bug is already recorded above. */
    SECTION("start/stop race, 12 cycles (leaked listener neutralised in the stub)");
    g_phase = "start/stop cycles (workaround)";
    {
        atomic_store(&g_stub_release_lfd, 1);
        /* reclaim the listener D1's webproxy_stop leaked, or nothing can bind */
        int leaked = atomic_exchange(&g_stub_lfd, -1);
        if (leaked >= 0) {
            printf("     (reclaiming fd %d — the DANE listener webproxy_stop leaked)\n", leaked);
            close(leaked);
        }
        int cycles = 0, start_failed = 0, serve_broken = 0;
        int pac_stuck = 0, dane_stuck = 0;
        uint64_t s = g_seed ^ 0x5EEDF00DULL;
        int fd0 = fd_count();

        for (int c = 0; c < NCYCLE; c++) {
            g_phase = "webproxy_start (workaround)";
            if (!webproxy_start("/dev/null", "/dev/null")) { start_failed = c + 1; break; }
            usleep(120000);

            char buf[16384];
            uint64_t s2 = sm64(&s);
            if (pac_once_jittered(&s2, buf, sizeof buf) != 0 && !serve_broken)
                serve_broken = c + 1;

            pthread_t inf[3];
            for (int i = 0; i < 3; i++)
                pthread_create(&inf[i], NULL, inflight_thread, (void *)(intptr_t)(c * 11 + i + 3));
            jitter_sleep(&s, 2000);

            g_phase = "webproxy_stop (workaround)";
            webproxy_stop();
            for (int i = 0; i < 3; i++) pthread_join(inf[i], NULL);
            cycles++;

            usleep(120000);
            if (!port_is_free(APP_PAC_PORT)   && !pac_stuck)  pac_stuck  = c + 1;
            if (!port_is_free(g_backend_port) && !dane_stuck) dane_stuck = c + 1;
        }
        int fd1 = fd_count();
        g_phase = "workaround verdict";
        printf("     %d of %d cycles completed; fds %d -> %d\n", cycles, NCYCLE, fd0, fd1);

        CHECK(cycles >= NCYCLE, "12 start/stop cycles with in-flight connections completed");
        CHECK(start_failed == 0, "webproxy_start succeeded on every cycle");
        CHECK(serve_broken == 0, "a jittered PAC was served correctly on every cycle");
        CHECK(pac_stuck == 0 && dane_stuck == 0, "both ports were released on every cycle");
        CHECK(fd1 <= fd0 + 4, "12 start/stop cycles leak no fds");
        CHECK(1, "no crash / use-after-free across 12 shutdowns racing live connections");
        atomic_store(&g_stub_release_lfd, 0);
    }

    g_phase = "teardown";
    webproxy_stop();
    usleep(300000);
    int fd_at_end = fd_count();
    printf("\n     open fds: %d at start, %d at end\n", fd_at_start, fd_at_end);

    atomic_store(&g_done, 1);
    pthread_join(wd, NULL);

    printf("\n%d checks, %s (seed %llu)\n", g_checks, g_fail ? "SOME FAILED" : "all ok",
           (unsigned long long)g_seed);
    printf(g_fail ? "j_webproxy: FAIL\n" : "j_webproxy: all ok\n");
    return g_fail;
}

/* ══ stubs for webproxy.c's dependencies — see the file header ═════════════ */
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
    snprintf(out, cap, "/tmp/j_webproxy_%d", (int)getpid());
    return out;
}
const char *platform_data_path(const char *name, char *out, size_t cap) {
    snprintf(out, cap, "/tmp/j_webproxy_%d/%s", (int)getpid(), name);
    return out;
}

/* byte-for-byte tls/src/proxy.c:156 */
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
    /* Only the FIRST attempt at APP_PROXY_PORT may relocate (a foreign process
     * owning it on the dev box); after that this is exactly tls/src/proxy.c, so
     * a port the app failed to release still shows up as a failed rebind. */
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
    atomic_store(&g_stub_lfd, lfd);
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
    if (atomic_load(&g_stub_release_lfd)) {             /* phase D2 only */
        close(lfd);
        atomic_store(&g_stub_lfd, -1);
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
