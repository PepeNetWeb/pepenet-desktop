/* test_serve_accept.c — production idx_serve connection-loop regressions.
 *
 * Speaks the real pep P2P framing against a live idx_serve thread (the same
 * function dnsd embeds). No success stub: a CHECK passes only if the wire
 * handshake, cap refusal, or EOF-freeing actually happened.
 *
 * Temporary dirs are under /tmp (never ~/.pepenet). Ports are ephemeral and
 * never 15353/8443/8444/8445.
 */
#include "indexer.h"
#include "db.h"
#include "sha256.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static int g_fail;
extern int idx_serve_send_eagain;
extern int idx_serve_send_partial;
#ifdef IDX_SERVE_TEST
extern const char *idx_serve_inject_fail_cmd;
#endif

#define CHECK(cond, name) do { \
    if (cond) printf("ok   %s\n", name); \
    else      { printf("FAIL %s\n", name); g_fail = 1; } \
} while (0)

static const uint8_t PEP_MAGIC[4] = { 0xC0, 0xA0, 0xF0, 0xE0 };

static double mono_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int forbidden_port(unsigned p) {
    return p == 15353 || p == 8443 || p == 8444 || p == 8445 || p == 33874 || p == 53;
}

static uint16_t pick_port(void) {
    for (int n = 0; n < 32; n++) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) return 0;
        int yes = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
        struct sockaddr_in a; memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) { close(s); continue; }
        socklen_t sl = sizeof a;
        if (getsockname(s, (struct sockaddr *)&a, &sl) != 0) { close(s); continue; }
        uint16_t p = ntohs(a.sin_port);
        close(s);
        if (p && !forbidden_port(p)) return p;
    }
    return 0;
}

static int listen_on(const char *ip, uint16_t *port_out) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    int yes = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    if (!ip || inet_pton(AF_INET, ip, &a.sin_addr) != 1)
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) { close(s); return -1; }
    socklen_t sl = sizeof a;
    if (getsockname(s, (struct sockaddr *)&a, &sl) != 0) { close(s); return -1; }
    uint16_t p = ntohs(a.sin_port);
    if (!p || forbidden_port(p) || listen(s, 32) != 0) { close(s); return -1; }
    *port_out = p;
    return s;
}

static int connect_from(const char *src, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (src && *src) {
        struct sockaddr_in b; memset(&b, 0, sizeof b);
        b.sin_family = AF_INET;
        if (inet_pton(AF_INET, src, &b.sin_addr) != 1) { close(fd); return -1; }
        if (bind(fd, (struct sockaddr *)&b, sizeof b) != 0) { close(fd); return -1; }
    }
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    int r = connect(fd, (struct sockaddr *)&a, sizeof a);
    if (r != 0 && errno != EINPROGRESS) { close(fd); return -1; }
    struct pollfd p = { fd, POLLOUT, 0 };
    if (poll(&p, 1, 2000) <= 0) { close(fd); return -1; }
    int err = 0; socklen_t el = sizeof err;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) { close(fd); return -1; }
    fcntl(fd, F_SETFL, fl);
    return fd;
}

static void sha256d(const uint8_t *d, size_t n, uint8_t o[32]) {
    uint8_t t[32]; SHA256_CTX c;
    sha256_init(&c); sha256_update(&c, d, (unsigned)n); sha256_final(&c, t);
    sha256_init(&c); sha256_update(&c, t, 32); sha256_final(&c, o);
}

static int write_all(int fd, const uint8_t *b, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = send(fd, b + off, n - off, MSG_NOSIGNAL);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return 0;
        off += (size_t)w;
    }
    return 1;
}

static int send_msg(int fd, const char *cmd, const uint8_t *pay, uint32_t len, int split) {
    uint8_t hdr[24]; memset(hdr, 0, 24);
    memcpy(hdr, PEP_MAGIC, 4);
    strncpy((char *)hdr + 4, cmd, 12);
    hdr[16] = (uint8_t)len; hdr[17] = (uint8_t)(len >> 8);
    hdr[18] = (uint8_t)(len >> 16); hdr[19] = (uint8_t)(len >> 24);
    uint8_t ck[32]; sha256d(pay ? pay : (const uint8_t *)"", len, ck);
    memcpy(hdr + 20, ck, 4);
    if (split) {
        if (!write_all(fd, hdr, 10)) return 0;
        if (!write_all(fd, hdr + 10, 14)) return 0;
        if (len && !write_all(fd, pay, len)) return 0;
        return 1;
    }
    if (!write_all(fd, hdr, 24)) return 0;
    if (len && !write_all(fd, pay, len)) return 0;
    return 1;
}

static int wait_read(int fd, int timeout_ms) {
    struct pollfd p = { fd, POLLIN, 0 };
    int r = poll(&p, 1, timeout_ms);
    return r > 0 && (p.revents & POLLIN);
}

static int recv_msg(int fd, char cmd[13], uint8_t *pay, uint32_t cap, uint32_t *len, int timeout_ms) {
    uint8_t hdr[24];
    size_t got = 0;
    double deadline = mono_now() + timeout_ms / 1000.0;
    while (got < 24) {
        int left = (int)((deadline - mono_now()) * 1000.0);
        if (left <= 0 || !wait_read(fd, left)) return 0;
        ssize_t r = recv(fd, hdr + got, 24 - got, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return 0;
        got += (size_t)r;
    }
    if (memcmp(hdr, PEP_MAGIC, 4) != 0) return -1;
    memcpy(cmd, hdr + 4, 12); cmd[12] = 0;
    uint32_t l = (uint32_t)hdr[16] | ((uint32_t)hdr[17] << 8) |
                 ((uint32_t)hdr[18] << 16) | ((uint32_t)hdr[19] << 24);
    if (l > cap) return -1;
    got = 0;
    while (got < l) {
        int left = (int)((deadline - mono_now()) * 1000.0);
        if (left <= 0 || !wait_read(fd, left)) return 0;
        ssize_t r = recv(fd, pay + got, l - got, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return 0;
        got += (size_t)r;
    }
    uint8_t ck[32]; sha256d(l ? pay : (const uint8_t *)"", l, ck);
    if (memcmp(hdr + 20, ck, 4) != 0) return -1;
    *len = l;
    return 1;
}

static int build_version(uint8_t *v, size_t cap, const char *agent, uint64_t nonce) {
    int o = 0;
    uint32_t proto = 70015;
    for (int i = 0; i < 4; i++) v[o++] = (uint8_t)((proto >> (8 * i)) & 0xff);
    for (int i = 0; i < 8; i++) v[o++] = 0;                 /* services */
    int64_t now = (int64_t)time(NULL);
    for (int i = 0; i < 8; i++) v[o++] = (uint8_t)((now >> (8 * i)) & 0xff);
    memset(v + o, 0, 26); o += 26;
    memset(v + o, 0, 26); o += 26;
    for (int i = 0; i < 8; i++) v[o++] = (uint8_t)((nonce >> (8 * i)) & 0xff);
    size_t ual = strlen(agent); if (ual > 100) ual = 100;
    v[o++] = (uint8_t)ual; memcpy(v + o, agent, ual); o += (int)ual;
    for (int i = 0; i < 4; i++) v[o++] = 0;                 /* start_height */
    v[o++] = 1;                                             /* relay */
    (void)cap;
    return o;
}

/* Inbound client: we speak first. Returns 1 on version+verack both ways. */
static int handshake_inbound(int fd, const char *agent, int split, int timeout_ms) {
    uint8_t ver[256];
    int vl = build_version(ver, sizeof ver, agent, 0x1111222233334444ULL);
    if (!send_msg(fd, "version", ver, (uint32_t)vl, split)) return 0;
    int got_v = 0, got_k = 0, sent_k = 0;
    double deadline = mono_now() + timeout_ms / 1000.0;
    while ((!(got_v && got_k) || !sent_k) && mono_now() < deadline) {
        char cmd[13]; uint8_t pay[512]; uint32_t pn = 0;
        int left = (int)((deadline - mono_now()) * 1000.0);
        if (left <= 0) break;
        int r = recv_msg(fd, cmd, pay, sizeof pay, &pn, left);
        if (r != 1) return 0;
        if (!strcmp(cmd, "version")) {
            got_v = 1;
            if (!sent_k) { if (!send_msg(fd, "verack", NULL, 0, 0)) return 0; sent_k = 1; }
        } else if (!strcmp(cmd, "verack")) {
            got_k = 1;
        } else if (!strcmp(cmd, "ping")) {
            send_msg(fd, "pong", pay, pn, 0);
        }
    }
    return got_v && got_k && sent_k;
}

/* We are the peer the seed dials: they speak first. */
static int handshake_as_dialed(int fd, const char *agent, int timeout_ms) {
    int got_v = 0, sent_v = 0, got_k = 0;
    double deadline = mono_now() + timeout_ms / 1000.0;
    while ((!(got_v && got_k) || !sent_v) && mono_now() < deadline) {
        char cmd[13]; uint8_t pay[512]; uint32_t pn = 0;
        int left = (int)((deadline - mono_now()) * 1000.0);
        if (left <= 0) break;
        int r = recv_msg(fd, cmd, pay, sizeof pay, &pn, left);
        if (r != 1) return 0;
        if (!strcmp(cmd, "version")) {
            got_v = 1;
            if (!sent_v) {
                uint8_t ver[256];
                int vl = build_version(ver, sizeof ver, agent, 0xaaaabbbbccccddddULL);
                if (!send_msg(fd, "version", ver, (uint32_t)vl, 0)) return 0;
                if (!send_msg(fd, "verack", NULL, 0, 0)) return 0;
                sent_v = 1;
            }
        } else if (!strcmp(cmd, "verack")) {
            got_k = 1;
        } else if (!strcmp(cmd, "ping")) {
            send_msg(fd, "pong", pay, pn, 0);
        }
    }
    return got_v && sent_v && got_k;
}

struct seed_ctx {
    char db[512];
    uint16_t port;
    char dial[160];
    volatile int stop;
    int rc;
};

static void *seed_thread(void *u) {
    struct seed_ctx *c = u;
    const char *dial = c->dial[0] ? c->dial : NULL;
    c->rc = idx_serve("pep", c->db, c->port, dial, &c->stop, NULL);
    return NULL;
}

static int start_seed(struct seed_ctx *c, pthread_t *th, const char *dir, const char *dial) {
    memset(c, 0, sizeof *c);
    snprintf(c->db, sizeof c->db, "%s/node.db", dir);
    c->port = pick_port();
    if (!c->port) return 0;
    if (dial) snprintf(c->dial, sizeof c->dial, "%s", dial);
    c->stop = 0; c->rc = -99;
    if (pthread_create(th, NULL, seed_thread, c) != 0) return 0;
    for (int i = 0; i < 100; i++) {
        int fd = connect_from(NULL, c->port);
        if (fd >= 0) { close(fd); return 1; }
        usleep(20000);
    }
    c->stop = 1; pthread_join(*th, NULL);
    return 0;
}

static void stop_seed(struct seed_ctx *c, pthread_t *th) {
    c->stop = 1;
    pthread_join(*th, NULL);
}

struct hole {
    int lfd;
    volatile int stop;
    volatile int accepted;
};

static void *hole_thread(void *u) {
    struct hole *h = u;
    int held[16]; int n = 0;
    while (!h->stop) {
        struct pollfd p = { h->lfd, POLLIN, 0 };
        if (poll(&p, 1, 100) > 0 && (p.revents & POLLIN)) {
            int c = accept(h->lfd, NULL, NULL);
            if (c >= 0) {
                h->accepted = 1;
                if (n < 16) held[n++] = c;
                else close(c);
            }
        }
    }
    for (int i = 0; i < n; i++) close(held[i]);
    return NULL;
}

static int wait_accepted(struct hole *h, int timeout_ms) {
    double d = mono_now() + timeout_ms / 1000.0;
    while (mono_now() < d) {
        if (h->accepted) return 1;
        usleep(10000);
    }
    return h->accepted;
}

static int rm_rf(const char *dir) {
    char cmd[640];
    snprintf(cmd, sizeof cmd, "rm -rf -- %s", dir);
    return system(cmd);
}

int main(void) {
    char dir[] = "/tmp/serve-accept-XXXXXX";
    if (!mkdtemp(dir)) { fprintf(stderr, "mkdtemp failed\n"); return 1; }

    uint16_t hole_port = 0;
    struct hole hole = {0};
    hole.lfd = listen_on("127.0.0.3", &hole_port);
    CHECK(hole.lfd >= 0 && hole_port, "blackhole listen");
    pthread_t hole_th;
    if (hole.lfd >= 0) pthread_create(&hole_th, NULL, hole_thread, &hole);

    char dial[80] = "";
    if (hole_port) snprintf(dial, sizeof dial, "127.0.0.3:%u", hole_port);

    struct seed_ctx seed;
    pthread_t sth;
    CHECK(start_seed(&seed, &sth, dir, dial), "idx_serve listen");

    CHECK(wait_accepted(&hole, 8000), "seed outbound reached blackhole (after 5s dial grace)");

    /* 1+2) inbound + burst must complete *while* the blocking outbound handshake
     * is still in progress (do not serialize behind the first handshake). */
    {
        int first = connect_from("127.0.0.1", seed.port);
        CHECK(first >= 0, "inbound connect during outbound stall");
        int fds[8];
        for (int i = 0; i < 8; i++) {
            char src[32]; snprintf(src, sizeof src, "127.0.0.%d", 11 + i);
            fds[i] = connect_from(src, seed.port);
        }
        double t0 = mono_now();
        int ok = first >= 0 && handshake_inbound(first, "/pepenet-desktop:test/", 0, 8000);
        double dt1 = mono_now() - t0;
        printf("info inbound-during-stall %.3fs ok=%d\n", dt1, ok);
        CHECK(ok, "inbound handshake during outbound stall");
        CHECK(ok && dt1 < 2.5, "inbound handshake during stall finished in <2.5s");
        int nok = 0;
        for (int i = 0; i < 8; i++) {
            if (fds[i] < 0) continue;
            const char *ag = (i & 1) ? "/bitcore-pepe:11.4.1/" : "/pepenet-desktop:test/";
            if (handshake_inbound(fds[i], ag, 1, 8000)) nok++;
        }
        double dt = mono_now() - t0;
        printf("info burst-during-stall %d/8 in %.3fs\n", nok, dt);
        CHECK(nok == 8, "burst 8 inbound handshakes during outbound stall");
        CHECK(nok == 8 && dt < 3.0, "burst 8 during stall finished in <3s");
        if (first >= 0) close(first);
        for (int i = 0; i < 8; i++) if (fds[i] >= 0) close(fds[i]);
    }

    /* 3) cap still 3/host; 4th refused; EOF frees a seat promptly during stall. */
    {
        int live[3] = { -1, -1, -1 };
        int got = 0;
        for (int i = 0; i < 3; i++) {
            live[i] = connect_from("127.0.0.1", seed.port);
            if (live[i] >= 0 && handshake_inbound(live[i], "/pepenet-desktop:test/", 0, 4000))
                got++;
            else if (live[i] >= 0) { close(live[i]); live[i] = -1; }
        }
        CHECK(got == 3, "three same-IP inbound seats allowed");
        int fourth = connect_from("127.0.0.1", seed.port);
        int refused = 0;
        if (fourth >= 0) {
            uint8_t ver[256];
            int vl = build_version(ver, sizeof ver, "/pepenet-desktop:test/", 1);
            send_msg(fourth, "version", ver, (uint32_t)vl, 0);
            char cmd[13]; uint8_t pay[512]; uint32_t pn = 0;
            int r = recv_msg(fourth, cmd, pay, sizeof pay, &pn, 1500);
            refused = (r != 1);   /* cap close → EOF/timeout, not a version */
            close(fourth);
        }
        CHECK(refused, "fourth same-IP inbound refused (cap 3)");

        int other = connect_from("127.0.0.2", seed.port);
        int other_ok = other >= 0 && handshake_inbound(other, "/pepenet-desktop:test/", 0, 4000);
        CHECK(other_ok, "different IP not charged against 127.0.0.1 cap");
        if (other >= 0) close(other);

        for (int i = 0; i < 3; i++) if (live[i] >= 0) { shutdown(live[i], SHUT_RDWR); close(live[i]); live[i] = -1; }
        double t0 = mono_now();
        int retry = -1, retry_ok = 0;
        for (int spin = 0; spin < 50 && !retry_ok; spin++) {
            usleep(20000);
            retry = connect_from("127.0.0.1", seed.port);
            if (retry < 0) continue;
            if (handshake_inbound(retry, "/pepenet-desktop:test/", 0, 2000)) {
                retry_ok = 1; break;
            }
            close(retry); retry = -1;
        }
        double dt = mono_now() - t0;
        printf("info eof-frees-seat %.3fs ok=%d\n", dt, retry_ok);
        CHECK(retry_ok, "EOF frees a cap seat");
        CHECK(retry_ok && dt < 2.5, "EOF frees a cap seat in <2.5s during stall");
        if (retry >= 0) close(retry);
    }

    stop_seed(&seed, &sth);
    CHECK(seed.rc == 0, "idx_serve shutdown rc=0");

    /* 4) outbound handshake compatibility with a live marked (and unmarked) peer. */
    {
        uint16_t peer_port = 0;
        int pl = listen_on("127.0.0.1", &peer_port);
        CHECK(pl >= 0, "compat peer listen");
        char d2[80]; snprintf(d2, sizeof d2, "127.0.0.1:%u", peer_port);
        char dir2[] = "/tmp/serve-accept-XXXXXX";
        if (!mkdtemp(dir2)) { CHECK(0, "mkdtemp compat"); }
        else {
            struct seed_ctx s2; pthread_t t2;
            CHECK(start_seed(&s2, &t2, dir2, d2), "idx_serve outbound compat");
            int cfd = -1;
            double until = mono_now() + 8.0;
            while (mono_now() < until && cfd < 0) {
                struct pollfd p = { pl, POLLIN, 0 };
                if (poll(&p, 1, 200) > 0) cfd = accept(pl, NULL, NULL);
            }
            CHECK(cfd >= 0, "seed dialed marked compat peer");
            int ok = cfd >= 0 && handshake_as_dialed(cfd, "/pepenet-dnsd:0.1/", 4000);
            CHECK(ok, "outbound handshake with marked peer");
            if (cfd >= 0) close(cfd);
            /* second cycle: new seed, unmarked chain-like agent */
            stop_seed(&s2, &t2);
            char dir3[] = "/tmp/serve-accept-XXXXXX";
            if (mkdtemp(dir3)) {
                struct seed_ctx s3; pthread_t t3;
                CHECK(start_seed(&s3, &t3, dir3, d2), "idx_serve unmarked outbound");
                int ufd = -1;
                until = mono_now() + 8.0;
                while (mono_now() < until && ufd < 0) {
                    struct pollfd p = { pl, POLLIN, 0 };
                    if (poll(&p, 1, 200) > 0) ufd = accept(pl, NULL, NULL);
                }
                int uok = ufd >= 0 && handshake_as_dialed(ufd, "/Satoshi:22.0.0/", 4000);
                CHECK(uok, "outbound handshake with unmarked chain-like peer");
                if (ufd >= 0) close(ufd);
                stop_seed(&s3, &t3);
                rm_rf(dir3);
            }
            rm_rf(dir2);
        }
        if (pl >= 0) close(pl);
    }

    /* 5) connect-refused failure path does not lock inbound. */
    {
        char dir4[] = "/tmp/serve-accept-XXXXXX";
        uint16_t closed = pick_port();
        char d4[80]; snprintf(d4, sizeof d4, "127.0.0.1:%u", closed);
        if (mkdtemp(dir4)) {
            struct seed_ctx s4; pthread_t t4;
            CHECK(start_seed(&s4, &t4, dir4, d4), "idx_serve with refused outbound");
            int fd = connect_from("127.0.0.1", s4.port);
            double t0 = mono_now();
            int ok = fd >= 0 && handshake_inbound(fd, "/pepenet-desktop:test/", 0, 4000);
            double dt = mono_now() - t0;
            printf("info inbound-with-refused-dial %.3fs ok=%d\n", dt, ok);
            CHECK(ok && dt < 2.5, "inbound works while outbound connect is refused");
            if (fd >= 0) close(fd);
            stop_seed(&s4, &t4);
            rm_rf(dir4);
        }
    }

    hole.stop = 1;
    if (hole.lfd >= 0) { pthread_join(hole_th, NULL); close(hole.lfd); }
    rm_rf(dir);

    /* 6) inbound-only cap: 3 inbound from 127.0.0.1 while a connecting
     * outbound targets the same IP (baseline counted only inbound). */
    {
        uint16_t hp = 0;
        struct hole same = {0};
        same.lfd = listen_on("127.0.0.1", &hp);
        CHECK(same.lfd >= 0 && hp, "same-ip outbound listen");
        pthread_t same_th;
        if (same.lfd >= 0) pthread_create(&same_th, NULL, hole_thread, &same);
        char d6[80]; snprintf(d6, sizeof d6, "127.0.0.1:%u", hp);
        char dir6[] = "/tmp/serve-accept-XXXXXX";
        if (mkdtemp(dir6) && same.lfd >= 0) {
            struct seed_ctx s6; pthread_t t6;
            CHECK(start_seed(&s6, &t6, dir6, d6), "idx_serve outbound to 127.0.0.1");
            CHECK(wait_accepted(&same, 8000), "outbound connecting to 127.0.0.1");
            int live[3] = { -1, -1, -1 }, got = 0;
            for (int i = 0; i < 3; i++) {
                live[i] = connect_from("127.0.0.1", s6.port);
                if (live[i] >= 0 && handshake_inbound(live[i], "/pepenet-desktop:test/", 0, 4000))
                    got++;
                else if (live[i] >= 0) { close(live[i]); live[i] = -1; }
            }
            CHECK(got == 3, "three inbound from 127.0.0.1 while outbound connecting to 127.0.0.1");
            int fourth = connect_from("127.0.0.1", s6.port);
            int refused = 0;
            if (fourth >= 0) {
                uint8_t ver[256];
                int vl = build_version(ver, sizeof ver, "/pepenet-desktop:test/", 2);
                send_msg(fourth, "version", ver, (uint32_t)vl, 0);
                char cmd[13]; uint8_t pay[512]; uint32_t pn = 0;
                refused = (recv_msg(fourth, cmd, pay, sizeof pay, &pn, 1500) != 1);
                close(fourth);
            }
            CHECK(refused, "fourth inbound still refused (cap 3, outbound not counted)");
            for (int i = 0; i < 3; i++) if (live[i] >= 0) close(live[i]);
            stop_seed(&s6, &t6);
            rm_rf(dir6);
        }
        same.stop = 1;
        if (same.lfd >= 0) { pthread_join(same_th, NULL); close(same.lfd); }
    }

    /* 7) outbound handshake completeness: up (dngetaddr) only after our verack. */
    {
        uint16_t pp = 0;
        int pl = listen_on("127.0.0.1", &pp);
        CHECK(pl >= 0, "ordering peer listen");
        char d7[80]; snprintf(d7, sizeof d7, "127.0.0.1:%u", pp);
        char dir7[] = "/tmp/serve-accept-XXXXXX";
        if (mkdtemp(dir7) && pl >= 0) {
            struct seed_ctx s7; pthread_t t7;
            CHECK(start_seed(&s7, &t7, dir7, d7), "idx_serve handshake-order seed");
            int cfd = -1;
            double until = mono_now() + 8.0;
            while (mono_now() < until && cfd < 0) {
                struct pollfd pfd = { pl, POLLIN, 0 };
                if (poll(&pfd, 1, 200) > 0) cfd = accept(pl, NULL, NULL);
            }
            CHECK(cfd >= 0, "seed dialed ordering peer");
            int saw_ver = 0, saw_early = 0, saw_verack = 0, saw_dnget = 0;
            if (cfd >= 0) {
                char cmd[13]; uint8_t pay[4096]; uint32_t pn = 0;
                int r = recv_msg(cfd, cmd, pay, sizeof pay, &pn, 4000);
                if (r == 1 && !strcmp(cmd, "version")) {
                    saw_ver = 1;
                    uint8_t ver[256];
                    int vl = build_version(ver, sizeof ver, "/pepenet-dnsd:0.1/", 0x5555ULL);
                    send_msg(cfd, "version", ver, (uint32_t)vl, 0);
                    /* they should send verack; must NOT go up (dngetaddr) yet */
                    double dline = mono_now() + 1.5;
                    while (mono_now() < dline) {
                        r = recv_msg(cfd, cmd, pay, sizeof pay, &pn, 300);
                        if (r != 1) break;
                        if (!strcmp(cmd, "verack")) saw_verack = 1;
                        else if (!strcmp(cmd, "dngetaddr") || !strcmp(cmd, "inv") ||
                                 !strcmp(cmd, "addr") || !strcmp(cmd, "getaddr"))
                            saw_early = 1;
                    }
                    send_msg(cfd, "verack", NULL, 0, 0);
                    dline = mono_now() + 3.0;
                    while (mono_now() < dline && !saw_dnget) {
                        r = recv_msg(cfd, cmd, pay, sizeof pay, &pn, 500);
                        if (r != 1) continue;
                        if (!strcmp(cmd, "dngetaddr")) saw_dnget = 1;
                    }
                    close(cfd);
                }
            }
            printf("info handshake-order ver=%d verack=%d early=%d dnget=%d\n",
                   saw_ver, saw_verack, saw_early, saw_dnget);
            CHECK(saw_ver && saw_verack && !saw_early, "no overlay cmds before client verack");
            CHECK(saw_dnget, "dngetaddr only after version+verack (up complete)");
            stop_seed(&s7, &t7);
            rm_rf(dir7);
        }
        if (pl >= 0) close(pl);
    }

#ifdef IDX_SERVE_TEST
    /* 7b) serve_send failure/overflow must not stamp last_dnget/dn_asked on
     * the reset outbound seat (that would delay the next dngetaddr by
     * DNADDR_REFRESH_S = 60s). Inject models overflow/hard-fail (drop + 0). */
    {
        uint16_t pp = 0;
        int pl = listen_on("127.0.0.1", &pp);
        CHECK(pl >= 0, "postdrop peer listen");
        char d7b[80]; snprintf(d7b, sizeof d7b, "127.0.0.1:%u", pp);
        char dir7b[] = "/tmp/serve-accept-XXXXXX";
        if (mkdtemp(dir7b) && pl >= 0) {
            struct seed_ctx s7b; pthread_t t7b;
            CHECK(start_seed(&s7b, &t7b, dir7b, d7b), "idx_serve postdrop seed");
            int cfd = -1;
            double until = mono_now() + 8.0;
            while (mono_now() < until && cfd < 0) {
                struct pollfd pfd = { pl, POLLIN, 0 };
                if (poll(&pfd, 1, 200) > 0) cfd = accept(pl, NULL, NULL);
            }
            CHECK(cfd >= 0, "seed dialed postdrop peer");
            int dropped = 0;
            if (cfd >= 0) {
                char cmd[13]; uint8_t pay[512]; uint32_t pn = 0;
                int r = recv_msg(cfd, cmd, pay, sizeof pay, &pn, 4000);
                if (r == 1 && !strcmp(cmd, "version")) {
                    idx_serve_inject_fail_cmd = "dngetaddr";
                    uint8_t ver[256];
                    int vl = build_version(ver, sizeof ver, "/pepenet-dnsd:0.1/", 0x6666ULL);
                    send_msg(cfd, "version", ver, (uint32_t)vl, 0);
                    send_msg(cfd, "verack", NULL, 0, 0);
                    /* they may still deliver verack; failed dngetaddr then drops */
                    double dline = mono_now() + 2.5;
                    while (mono_now() < dline) {
                        r = recv_msg(cfd, cmd, pay, sizeof pay, &pn, 400);
                        if (r != 1) { dropped = 1; break; }
                    }
                }
                close(cfd);
            }
            CHECK(dropped, "dngetaddr send failure dropped the peer");
            int cfd2 = -1;
            until = mono_now() + 20.0; /* configured outbound redial_at is +15s */
            while (mono_now() < until && cfd2 < 0) {
                struct pollfd pfd = { pl, POLLIN, 0 };
                if (poll(&pfd, 1, 200) > 0) cfd2 = accept(pl, NULL, NULL);
            }
            CHECK(cfd2 >= 0, "outbound redialed after send-fail drop");
            int hok = 0, saw_dnget = 0;
            if (cfd2 >= 0) {
                hok = handshake_as_dialed(cfd2, "/pepenet-dnsd:0.1/", 4000);
                double dline = mono_now() + 4.0;
                while (mono_now() < dline && !saw_dnget) {
                    char cmd[13]; uint8_t pay[4096]; uint32_t pn = 0;
                    int r = recv_msg(cfd2, cmd, pay, sizeof pay, &pn, 500);
                    if (r == 1 && !strcmp(cmd, "dngetaddr")) saw_dnget = 1;
                }
                close(cfd2);
            }
            printf("info postdrop-redial handshake=%d dngetaddr=%d\n", hok, saw_dnget);
            CHECK(hok && saw_dnget, "no retained dngetaddr delay after post-drop (not 60s)");
            stop_seed(&s7b, &t7b);
            rm_rf(dir7b);
        }
        if (pl >= 0) close(pl);
    }
#endif

    /* 8) SERVER-SEND: small window + unread client forces EAGAIN/partial write;
     * queued pongs must drain as intact frames (not torn). */
    {
        setenv("IDX_SERVE_TEST_SNDBUF", "8192", 1);
        char dir8[] = "/tmp/serve-accept-XXXXXX";
        if (mkdtemp(dir8)) {
            struct seed_ctx s8; pthread_t t8;
            CHECK(start_seed(&s8, &t8, dir8, NULL), "idx_serve server-send seed");
            int fd = connect_from("127.0.0.1", s8.port);
            int ok = fd >= 0 && handshake_inbound(fd, "/pepenet-desktop:test/", 0, 4000);
            CHECK(ok, "server-send handshake");
            int before_e = idx_serve_send_eagain, before_p = idx_serve_send_partial;
            if (fd >= 0) {
                /* drain leftover post-handshake frames (dngetaddr) before
                 * shrinking the window — Linux may discard unread socket
                 * data when SO_RCVBUF is reduced, which would look like tear. */
                {
                    char cmd[13]; uint8_t pay[4096]; uint32_t pn = 0;
                    double dline = mono_now() + 0.3;
                    while (mono_now() < dline)
                        if (recv_msg(fd, cmd, pay, sizeof pay, &pn, 50) != 1) break;
                }
                /* server SNDBUF (IDX_SERVE_TEST_SNDBUF) is the small-window
                 * pressure; shrinking the client RCVBUF after handshake can
                 * discard unread bytes on Linux and is not required to force
                 * a nonblocking server send() EAGAIN. */
                int rsz = 4096;
                setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rsz, sizeof rsz);
                enum { NP = 10, PS = 4096 };
                uint8_t *pays = malloc((size_t)NP * PS);
                CHECK(pays != NULL, "server-send payload alloc");
                if (pays) {
                    for (int i = 0; i < NP; i++) {
                        memset(pays + i * PS, (uint8_t)(0xA0 + i), PS);
                        pays[i * PS] = (uint8_t)i;
                        send_msg(fd, "ping", pays + i * PS, PS, 0);
                    }
                    usleep(300000);
                    int eagain = idx_serve_send_eagain - before_e;
                    int partial = idx_serve_send_partial - before_p;
                    printf("info server-send eagain=%d partial=%d\n", eagain, partial);
                    CHECK(eagain > 0, "server send hit EAGAIN (queued remainder)");
                    int matched[10] = {0}, ngot = 0, torn = 0;
                    double dline = mono_now() + 8.0;
                    while (mono_now() < dline && ngot < NP && !torn) {
                        char cmd[13]; uint8_t pay[8192]; uint32_t pn = 0;
                        int r = recv_msg(fd, cmd, pay, sizeof pay, &pn, 500);
                        if (r == -1) { torn = 1; break; }
                        if (r != 1) continue;
                        if (strcmp(cmd, "pong")) continue;
                        if (pn != PS) { torn = 1; break; }
                        int hit = 0;
                        for (int i = 0; i < NP; i++) {
                            if (!matched[i] && memcmp(pay, pays + i * PS, PS) == 0) {
                                matched[i] = 1; ngot++; hit = 1; break;
                            }
                        }
                        if (!hit) { torn = 1; break; }
                    }
                    int after_e = idx_serve_send_eagain - before_e;
                    int after_p = idx_serve_send_partial - before_p;
                    printf("info server-send drained %d/%d torn=%d eagain=%d partial=%d\n",
                           ngot, NP, torn, after_e, after_p);
                    CHECK(!torn && ngot == NP, "server-send drained intact pong frames");
                    free(pays);
                }
                close(fd);
            }
            stop_seed(&s8, &t8);
            rm_rf(dir8);
        }
        unsetenv("IDX_SERVE_TEST_SNDBUF");
    }

    /* 9) inbound self-connect: echo seed nonce → centralized cleanup (LSan). */
    {
        char dir9[] = "/tmp/serve-accept-XXXXXX";
        if (mkdtemp(dir9)) {
            struct seed_ctx s9; pthread_t t9;
            CHECK(start_seed(&s9, &t9, dir9, NULL), "idx_serve self-connect seed");
            int fd = connect_from("127.0.0.1", s9.port);
            uint64_t nonce = 0;
            int got_nonce = 0;
            if (fd >= 0) {
                uint8_t ver[256];
                int vl = build_version(ver, sizeof ver, "/pepenet-desktop:test/", 0x9999ULL);
                send_msg(fd, "version", ver, (uint32_t)vl, 0);
                char cmd[13]; uint8_t pay[512]; uint32_t pn = 0;
                double dline = mono_now() + 4.0;
                while (mono_now() < dline) {
                    int r = recv_msg(fd, cmd, pay, sizeof pay, &pn, 500);
                    if (r != 1) break;
                    if (!strcmp(cmd, "version") && pn >= 80) {
                        nonce = 0;
                        for (int i = 0; i < 8; i++) nonce |= (uint64_t)pay[72 + i] << (8 * i);
                        got_nonce = nonce != 0;
                        send_msg(fd, "verack", NULL, 0, 0);
                    }
                }
                close(fd);
            }
            CHECK(got_nonce, "captured seed version nonce");
            int sfd = connect_from("127.0.0.1", s9.port);
            int closed = 0;
            if (sfd >= 0 && got_nonce) {
                uint8_t ver[256];
                int vl = build_version(ver, sizeof ver, "/pepenet-desktop:test/", nonce);
                send_msg(sfd, "version", ver, (uint32_t)vl, 0);
                char cmd[13]; uint8_t pay[512]; uint32_t pn = 0;
                int r = recv_msg(sfd, cmd, pay, sizeof pay, &pn, 2500);
                closed = (r != 1); /* drop → EOF/timeout, not a lasting handshake */
                /* a second inbound from another IP must still work (no leak/stall) */
                close(sfd);
            } else if (sfd >= 0) close(sfd);
            CHECK(closed, "self-connect inbound dropped");
            int other = connect_from("127.0.0.2", s9.port);
            int ook = other >= 0 && handshake_inbound(other, "/pepenet-desktop:test/", 0, 4000);
            CHECK(ook, "inbound still works after self-connect drop");
            if (other >= 0) close(other);
            stop_seed(&s9, &t9);
            rm_rf(dir9);
        }
    }

    /* 10) mesh feeler: pre-inserted unmarked dnet vouch is dialed, unmarked
     * handshake releases the seat without redial (LSan path). */
    {
        uint16_t fp = 0;
        int fl = listen_on("127.0.0.4", &fp);
        CHECK(fl >= 0, "feeler peer listen on 127.0.0.4");
        char dirf[] = "/tmp/serve-accept-XXXXXX";
        if (mkdtemp(dirf) && fl >= 0) {
            char dbp[512]; snprintf(dbp, sizeof dbp, "%s/node.db", dirf);
            sqlite3 *db = idx_db_open(dbp);
            CHECK(db != NULL, "feeler db open");
            if (db) {
                char addr[80]; snprintf(addr, sizeof addr, "127.0.0.4:%u", fp);
                idx_db_peer_dnet_note(db, addr, 0, (int64_t)time(NULL));
                idx_db_close(db);
            }
            struct seed_ctx sf; pthread_t tf;
            CHECK(start_seed(&sf, &tf, dirf, NULL), "idx_serve feeler seed");
            int cfd = -1;
            double until = mono_now() + 12.0; /* 5s dial grace + connect */
            while (mono_now() < until && cfd < 0) {
                struct pollfd pfd = { fl, POLLIN, 0 };
                if (poll(&pfd, 1, 200) > 0) cfd = accept(fl, NULL, NULL);
            }
            CHECK(cfd >= 0, "mesh feeler dialed vouched 127.0.0.4");
            int hok = 0, dropped = 0;
            if (cfd >= 0) {
                hok = handshake_as_dialed(cfd, "/Satoshi:22.0.0/", 4000);
                CHECK(hok, "unmarked feeler handshake (version+verack)");
                char cmd[13]; uint8_t pay[512]; uint32_t pn = 0;
                int r = recv_msg(cfd, cmd, pay, sizeof pay, &pn, 3000);
                dropped = (r != 1);
                close(cfd);
            }
            CHECK(dropped, "unmarked mesh feeler released (no retain)");
            int redial = 0;
            until = mono_now() + 2.5;
            while (mono_now() < until) {
                struct pollfd pfd = { fl, POLLIN, 0 };
                if (poll(&pfd, 1, 200) > 0) {
                    int nfd = accept(fl, NULL, NULL);
                    if (nfd >= 0) { redial = 1; close(nfd); break; }
                }
            }
            CHECK(!redial, "unmarked feeler not redialed immediately");
            int inbound = connect_from("127.0.0.1", sf.port);
            int iok = inbound >= 0 && handshake_inbound(inbound, "/pepenet-desktop:test/", 0, 4000);
            CHECK(iok, "inbound works after feeler release");
            if (inbound >= 0) close(inbound);
            stop_seed(&sf, &tf);
            rm_rf(dirf);
        }
        if (fl >= 0) close(fl);
    }

    if (!g_fail) printf("test_serve_accept: ALL PASSED\n");
    else printf("test_serve_accept: FAILED\n");
    return g_fail ? 1 : 0;
}
