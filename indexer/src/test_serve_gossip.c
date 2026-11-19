/* test_serve_gossip.c — production idx_serve + real dns_net + real sp_state.
 *
 * Isolated same-IP seating regression (synthetic oracle + locally signed
 * records). This is NOT production or cold-acceptance evidence.
 *
 * Temporary dirs are under /tmp (never ~/.pepenet). Ports are ephemeral and
 * never 15353/8443/8444/8445/33874/53.
 */
#include "indexer.h"
#include "dns_net.h"
#include "dns_state.h"
#include "pepenet/crypto.h"
#include "pepenet/state.h"
#include "sha256.h"
#include "zone.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifdef IDX_SERVE_TEST
extern const char *idx_serve_inject_fail_cmd;
#endif

static int g_fail;
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
        if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) { close(s); continue; }
        socklen_t sl = sizeof a;
        if (getsockname(s, (struct sockaddr *)&a, &sl) != 0) { close(s); continue; }
        uint16_t p = ntohs(a.sin_port);
        close(s);
        if (p && !forbidden_port(p)) return p;
    }
    return 0;
}

static int connect_loop(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in b; memset(&b, 0, sizeof b);
    b.sin_family = AF_INET;
    b.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&b, sizeof b) != 0) { close(fd); return -1; }
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
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) {
        close(fd); return -1;
    }
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

static int send_msg(int fd, const char *cmd, const uint8_t *pay, uint32_t len) {
    uint8_t hdr[24]; memset(hdr, 0, 24);
    memcpy(hdr, PEP_MAGIC, 4);
    strncpy((char *)hdr + 4, cmd, 12);
    hdr[16] = (uint8_t)len; hdr[17] = (uint8_t)(len >> 8);
    hdr[18] = (uint8_t)(len >> 16); hdr[19] = (uint8_t)(len >> 24);
    uint8_t ck[32]; sha256d(pay ? pay : (const uint8_t *)"", len, ck);
    memcpy(hdr + 20, ck, 4);
    if (!write_all(fd, hdr, 24)) return 0;
    if (len && !write_all(fd, pay, len)) return 0;
    return 1;
}

static int wait_read(int fd, int timeout_ms) {
    struct pollfd p = { fd, POLLIN, 0 };
    return poll(&p, 1, timeout_ms) > 0 && (p.revents & POLLIN);
}

static uint64_t rvar(const uint8_t *buf, uint32_t n, uint32_t *off) {
    if (*off >= n) return (uint64_t)-1;
    uint8_t b = buf[*off];
    if (b < 0xFD) { *off += 1; return b; }
    if (b == 0xFD) {
        if (*off + 3 > n) return (uint64_t)-1;
        uint64_t v = (uint64_t)buf[*off + 1] | ((uint64_t)buf[*off + 2] << 8);
        *off += 3; return v;
    }
    return (uint64_t)-1;
}

typedef struct { char cmd[16]; uint32_t plen; int items; } Obs;

static int recv_obs(int fd, Obs *o, uint8_t *pay, uint32_t cap, int timeout_ms) {
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
    memcpy(o->cmd, hdr + 4, 12); o->cmd[12] = 0;
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
    o->plen = l;
    o->items = -1;
    if (!strcmp(o->cmd, "dnzinv")) {
        uint32_t off = 0;
        uint64_t n = rvar(pay, l, &off);
        if (n != (uint64_t)-1 && n < 4096) o->items = (int)n;
    } else if (!strcmp(o->cmd, "dnzdat")) {
        if (l >= 1) {
            uint32_t off = 1u + pay[0];
            uint64_t n = rvar(pay, l, &off);
            if (n != (uint64_t)-1 && n < 256) o->items = (int)n;
        }
    } else if (!strcmp(o->cmd, "dnzget")) {
        o->items = 1;
    }
    return 1;
}

static int count_cmd(const Obs *o, int n, const char *cmd) {
    int c = 0;
    for (int i = 0; i < n; i++) if (!strcmp(o[i].cmd, cmd)) c++;
    return c;
}

static int items_for(const Obs *o, int n, const char *cmd) {
    for (int i = 0; i < n; i++)
        if (!strcmp(o[i].cmd, cmd) && o[i].items >= 0) return o[i].items;
    return -1;
}

typedef struct { Obs o[48]; int n; uint8_t zdat[8192]; uint32_t zdat_len; } Stash;

static int handshake(int fd, const char *agent, Stash *st) {
    uint8_t ver[256];
    int o = 0;
    uint32_t proto = 70015;
    for (int i = 0; i < 4; i++) ver[o++] = (uint8_t)((proto >> (8 * i)) & 0xff);
    for (int i = 0; i < 8; i++) ver[o++] = 0;
    int64_t now = (int64_t)time(NULL);
    for (int i = 0; i < 8; i++) ver[o++] = (uint8_t)((now >> (8 * i)) & 0xff);
    memset(ver + o, 0, 26); o += 26;
    memset(ver + o, 0, 26); o += 26;
    uint64_t nonce = 0x1111222233334444ULL;
    for (int i = 0; i < 8; i++) ver[o++] = (uint8_t)((nonce >> (8 * i)) & 0xff);
    size_t ual = strlen(agent); if (ual > 100) ual = 100;
    ver[o++] = (uint8_t)ual; memcpy(ver + o, agent, ual); o += (int)ual;
    for (int i = 0; i < 4; i++) ver[o++] = 0;
    ver[o++] = 1;
    if (!send_msg(fd, "version", ver, (uint32_t)o)) return 0;
    int got_v = 0, got_k = 0, sent_k = 0;
    double deadline = mono_now() + 4.0;
    uint8_t pay[16384];
    while ((!(got_v && got_k) || !sent_k) && mono_now() < deadline) {
        Obs ob; memset(&ob, 0, sizeof ob);
        int left = (int)((deadline - mono_now()) * 1000.0);
        int r = recv_obs(fd, &ob, pay, sizeof pay, left);
        if (r != 1) return 0;
        if (!strcmp(ob.cmd, "version")) {
            got_v = 1;
            if (!sent_k) {
                if (!send_msg(fd, "verack", NULL, 0)) return 0;
                sent_k = 1;
            }
        } else if (!strcmp(ob.cmd, "verack")) {
            got_k = 1;
        } else if (!strcmp(ob.cmd, "ping")) {
            send_msg(fd, "pong", pay, ob.plen);
        } else if (st && st->n < 48) {
            if (!strcmp(ob.cmd, "dnzdat") && ob.plen <= sizeof st->zdat) {
                memcpy(st->zdat, pay, ob.plen);
                st->zdat_len = ob.plen;
            }
            st->o[st->n++] = ob;
        }
    }
    return got_v && got_k && sent_k;
}

static int collect(int fd, Stash *st, int timeout_ms) {
    double deadline = mono_now() + timeout_ms / 1000.0;
    uint8_t pay[16384];
    while (st->n < 48 && mono_now() < deadline) {
        Obs ob; memset(&ob, 0, sizeof ob);
        int left = (int)((deadline - mono_now()) * 1000.0);
        if (left <= 0) break;
        int r = recv_obs(fd, &ob, pay, sizeof pay, left);
        if (r != 1) break;
        if (!strcmp(ob.cmd, "ping")) { send_msg(fd, "pong", pay, ob.plen); continue; }
        if (!strcmp(ob.cmd, "dnzdat") && ob.plen <= sizeof st->zdat) {
            memcpy(st->zdat, pay, ob.plen);
            st->zdat_len = ob.plen;
        }
        st->o[st->n++] = ob;
    }
    return st->n;
}

static uint32_t g_tip = 2000;
static uint8_t g_owner160[20];
static int fk_owner(void *u, const char *name, uint8_t owner[20]) {
    (void)u;
    if (strcmp(name, "zone") != 0) return 0;
    memcpy(owner, g_owner160, 20);
    return 1;
}
static int fk_header(void *u, uint32_t height, uint8_t out[32]) {
    (void)u;
    if (height > g_tip) return 0;
    uint8_t seed[8] = { 'h','d','r',1, (uint8_t)height, (uint8_t)(height >> 8),
                        (uint8_t)(height >> 16), (uint8_t)(height >> 24) };
    sp_sha256(seed, sizeof seed, out);
    return 1;
}
static uint32_t fk_tip(void *u) { (void)u; return g_tip; }
static SpChainOracle ORC = { NULL, fk_owner, fk_header, fk_tip };

static void testkey(const char *seed, uint8_t priv[32], uint8_t pub[33]) {
    sp_sha256((const uint8_t *)seed, strlen(seed), priv);
    while (!sp_pubkey(priv, pub)) sp_sha256(priv, 32, priv);
}

struct seed {
    char db[512];
    uint16_t port;
    volatile int stop;
    int rc;
};

static void *mesh_up(void *ud, void *peer,
                     void (*send)(void *peer, const char *cmd, const uint8_t *pay, size_t n)) {
    (void)ud;
    return dnsnet_up(peer, send);
}
static void mesh_msg(void *ud, void *handle, const char *name, const uint8_t *pay, int n) {
    (void)ud;
    dnsnet_msg(handle, name, pay, n);
}
static void mesh_down(void *ud, void *handle) {
    (void)ud;
    dnsnet_down(handle);
}
static void mesh_tick(void *ud) {
    (void)ud;
    dnsnet_tick();
}

static void *seed_thread(void *u) {
    struct seed *c = u;
    IdxMeshHooks hooks = { mesh_up, mesh_msg, mesh_down, mesh_tick, NULL, serve_conn_misbehave };
    c->rc = idx_serve("pep", c->db, c->port, NULL, &c->stop, &hooks);
    return NULL;
}

static int start_seed(struct seed *c, pthread_t *th, const char *dir) {
    memset(c, 0, sizeof *c);
    snprintf(c->db, sizeof c->db, "%s/node.db", dir);
    c->port = pick_port();
    if (!c->port) return 0;
    c->stop = 0; c->rc = -99;
    if (pthread_create(th, NULL, seed_thread, c) != 0) return 0;
    for (int i = 0; i < 100; i++) {
        int fd = connect_loop(c->port);
        if (fd >= 0) { close(fd); return 1; }
        usleep(20000);
    }
    c->stop = 1; pthread_join(*th, NULL);
    return 0;
}

static void stop_seed(struct seed *c, pthread_t *th) {
    c->stop = 1;
    pthread_join(*th, NULL);
}

static int fd_count(void) {
    DIR *d = opendir("/proc/self/fd");
    if (!d) return -1;
    int n = 0;
    while (readdir(d)) n++;
    closedir(d);
    return n;
}

static long rss_kb(void) {
    FILE *f = fopen("/proc/self/statm", "r");
    if (!f) return -1;
    long pages = 0, res = 0;
    if (fscanf(f, "%ld %ld", &pages, &res) != 2) { fclose(f); return -1; }
    fclose(f);
    long pg = sysconf(_SC_PAGESIZE);
    return res * (pg / 1024);
}

static int send_dngetaddr(int fd) { return send_msg(fd, "dngetaddr", NULL, 0); }

static int send_getblocks(int fd) {
    /* locator count 1 + 32 zero hash + 32 zero stop: enough to look like chain. */
    uint8_t p[1 + 64];
    memset(p, 0, sizeof p);
    p[0] = 1;
    return send_msg(fd, "getblocks", p, sizeof p);
}

int main(void) {
    char dir[] = "/tmp/serve-gossip-XXXXXX";
    if (!mkdtemp(dir)) { fprintf(stderr, "mkdtemp failed\n"); return 1; }
    char storep[640];
    snprintf(storep, sizeof storep, "%s/zones.db", dir);

    uint8_t opriv[32], opub[33];
    testkey("owner-gossip-seat", opriv, opub);
    sp_hash160(opub, 33, g_owner160);

    SpState *st = sp_state_open(storep);
    if (!st) { fprintf(stderr, "sp_state_open failed\n"); return 1; }
    zone_rec rec; memset(&rec, 0, sizeof rec);
    rec.type = 1; rec.ttl = 300; rec.rdlen = 4;
    rec.rdata[0] = 10; rec.rdata[1] = 0; rec.rdata[2] = 0; rec.rdata[3] = 1;
    char err[128] = {0};
    int put = dns_state_put(st, &ORC, "zone", &rec, opriv, opub,
                            SP_CERT_NONE, NULL, 0, err, sizeof err);
    CHECK(put == 1, "signed isolated record admitted to server store");
    dnsnet_init(st, ORC, 0);

    int fds0 = fd_count();
    long rss0 = rss_kb();
    printf("info handles_before fd=%d rss_kb=%ld\n", fds0, rss0);

    /* ── scenario 1: two legitimate same-IP overlay clients, cap room remains ── */
    {
        struct seed seed;
        pthread_t th;
        CHECK(start_seed(&seed, &th, dir), "idx_serve+dnsnet listen (A/B)");
        int a = connect_loop(seed.port);
        int b = -1;
        CHECK(a >= 0, "client A connect (127.0.0.1)");
        Stash sa; memset(&sa, 0, sizeof sa);
        CHECK(a >= 0 && handshake(a, "/pepenet-desktop:0.2.3/", &sa),
              "client A marked overlay handshake");
        if (a >= 0) send_dngetaddr(a);
        collect(a, &sa, 1500);
        int a_inv = count_cmd(sa.o, sa.n, "dnzinv");
        printf("info A dnzinv=%d items=%d (populated overlay already seated)\n",
               a_inv, items_for(sa.o, sa.n, "dnzinv"));
        CHECK(a_inv > 0, "client A received dnzinv (gossip seated)");

        b = connect_loop(seed.port);
        CHECK(b >= 0, "client B connect same 127.0.0.1 (2 of 3 cap)");
        Stash sb; memset(&sb, 0, sizeof sb);
        CHECK(b >= 0 && handshake(b, "/pepenet-desktop:0.2.3/", &sb),
              "client B marked empty overlay handshake");
        if (b >= 0) send_dngetaddr(b);
        collect(b, &sb, 1500);
        int b_inv = count_cmd(sb.o, sb.n, "dnzinv");
        int b_dat = count_cmd(sb.o, sb.n, "dnzdat");
        printf("info B dnzinv=%d dnzdat=%d items=%d\n",
               b_inv, b_dat, items_for(sb.o, sb.n, "dnzinv"));
        CHECK(b_inv > 0, "client B received dnzinv (not skipped peer_up)");
        if (b >= 0 && b_inv > 0) {
            uint8_t req[8]; req[0] = 4; memcpy(req + 1, "zone", 4);
            send_msg(b, "dnzget", req, 5);
            collect(b, &sb, 1500);
            b_dat = count_cmd(sb.o, sb.n, "dnzdat");
            printf("info B after dnzget dnzdat=%d items=%d\n",
                   b_dat, items_for(sb.o, sb.n, "dnzdat"));
            CHECK(b_dat > 0, "client B received dnzdat for empty store pull");
            /* admit captured dnzdat ops into a separate client store.
             * Same synthetic oracle as the server put — isolated regression
             * only, not production acceptance. Does not call dnsnet_msg
             * (process-global singleton already bound to the server store). */
            char cstore[640];
            snprintf(cstore, sizeof cstore, "%s/clientB.db", dir);
            SpState *bst = sp_state_open(cstore);
            int admitted = 0;
            if (bst && sb.zdat_len > 0) {
                const uint8_t *pay = sb.zdat;
                int n = (int)sb.zdat_len;
                uint32_t off = 0;
                int nlen = (n >= 1) ? pay[off++] : -1;
                if (nlen >= 1 && nlen <= 64 && off + (uint32_t)nlen <= (uint32_t)n) {
                    off += (uint32_t)nlen;
                    uint64_t count = rvar(pay, (uint32_t)n, &off);
                    if (count != (uint64_t)-1 && count < 256) {
                        for (uint64_t i = 0; i < count; i++) {
                            uint64_t ol = rvar(pay, (uint32_t)n, &off);
                            if (ol == (uint64_t)-1 || ol < 1 || off + (uint32_t)ol > (uint32_t)n) break;
                            const uint8_t *op = pay + off; off += (uint32_t)ol;
                            char e[128] = {0};
                            int rc = sp_state_admit(bst, &ORC, DNS_BUDGET, DNS_SCOPE,
                                                    op, (int)ol, e, sizeof e);
                            if (rc == 1) admitted++;
                        }
                    }
                    uint8_t dS[32], dB[32];
                    dns_state_digest(st, "zone", dS);
                    dns_state_digest(bst, "zone", dB);
                    printf("info B admitted=%d digest_match=%d\n",
                           admitted, memcmp(dS, dB, 32) == 0);
                    CHECK(admitted > 0, "client B admitted signed zone op into separate store");
                    CHECK(memcmp(dS, dB, 32) == 0,
                          "client B zone digest matches server (isolated)");
                } else {
                    CHECK(0, "client B dnzdat name prefix parseable");
                }
                sp_state_close(bst);
            } else {
                CHECK(0, "client B captured dnzdat payload for isolated admit");
                if (bst) sp_state_close(bst);
            }
            CHECK(b_dat > 0 && items_for(sb.o, sb.n, "dnzdat") >= 1,
                  "client B dnzdat carried at least one op (isolated)");
        }
        if (a >= 0) close(a);
        if (b >= 0) close(b);
        usleep(80000);
        printf("info peers after A/B close %d\n", dnsnet_peers());
        CHECK(dnsnet_peers() == 0, "dnsnet peer table reclaimed after A/B disconnect");
        stop_seed(&seed, &th);
    }

    /* Recreate store binding: dnsnet_init already bound `st`. idx_serve stopped;
     * dnsnet peer table should be emptied via peer_down. Re-init for a clean seat table. */
    dnsnet_init(st, ORC, 0);

    /* ── scenario 2: engine-sync inbound then overlay inbound, same IP ── */
    {
        char dir2[] = "/tmp/serve-gossip2-XXXXXX";
        if (!mkdtemp(dir2)) { CHECK(0, "mkdtemp engine/overlay"); }
        else {
            /* reuse same zone store file already populated; new chain db */
            struct seed seed;
            pthread_t th;
            CHECK(start_seed(&seed, &th, dir2), "idx_serve+dnsnet listen (E/O)");
            int e = connect_loop(seed.port);
            CHECK(e >= 0, "engine client E connect");
            Stash se; memset(&se, 0, sizeof se);
            CHECK(e >= 0 && handshake(e, "/pepenet-desktop:0.2.3/", &se),
                  "engine E marked handshake (no dn*)");
            if (e >= 0) send_getblocks(e);
            collect(e, &se, 1500);
            int e_inv = count_cmd(se.o, se.n, "dnzinv");
            printf("info E (engine, no dn*) dnzinv=%d\n", e_inv);
            CHECK(e_inv == 0, "engine-only inbound did not take a gossip seat");

            int ov = connect_loop(seed.port);
            CHECK(ov >= 0, "overlay client O connect same IP after engine");
            Stash so; memset(&so, 0, sizeof so);
            CHECK(ov >= 0 && handshake(ov, "/pepenet-desktop:0.2.3/", &so),
                  "overlay O marked handshake");
            if (ov >= 0) send_dngetaddr(ov);
            collect(ov, &so, 1500);
            int o_inv = count_cmd(so.o, so.n, "dnzinv");
            printf("info O (overlay after engine) dnzinv=%d items=%d\n",
                   o_inv, items_for(so.o, so.n, "dnzinv"));
            CHECK(o_inv > 0, "later overlay inbound received dnzinv after engine socket");
            if (e >= 0) close(e);
            if (ov >= 0) close(ov);
            stop_seed(&seed, &th);
            char rm[700]; snprintf(rm, sizeof rm, "rm -rf -- %s", dir2); system(rm);
        }
    }

    dnsnet_init(st, ORC, 0);

    /* ── scenario 3: 3/host cap unchanged (inbound only) ── */
    {
        char dir3[] = "/tmp/serve-gossip3-XXXXXX";
        if (!mkdtemp(dir3)) { CHECK(0, "mkdtemp cap"); }
        else {
            struct seed seed;
            pthread_t th;
            CHECK(start_seed(&seed, &th, dir3), "idx_serve listen (cap)");
            int live[3] = { -1, -1, -1 }, got = 0;
            for (int i = 0; i < 3; i++) {
                live[i] = connect_loop(seed.port);
                Stash s; memset(&s, 0, sizeof s);
                if (live[i] >= 0 && handshake(live[i], "/pepenet-desktop:0.2.3/", &s))
                    got++;
                else if (live[i] >= 0) { close(live[i]); live[i] = -1; }
            }
            CHECK(got == 3, "three same-IP inbound seats still allowed");
            int fourth = connect_loop(seed.port);
            int refused = 0;
            if (fourth >= 0) {
                uint8_t ver[8]; memset(ver, 0, sizeof ver);
                /* version will be sent by handshake; if cap refuses, recv fails or EOF */
                Stash s; memset(&s, 0, sizeof s);
                int okh = handshake(fourth, "/pepenet-desktop:0.2.3/", &s);
                if (!okh) refused = 1;
                close(fourth);
            } else refused = 1;
            CHECK(refused, "fourth same-IP inbound still refused (cap stays 3)");
            for (int i = 0; i < 3; i++) if (live[i] >= 0) close(live[i]);
            stop_seed(&seed, &th);
            char rm[700]; snprintf(rm, sizeof rm, "rm -rf -- %s", dir3); system(rm);
        }
    }

    dnsnet_init(st, ORC, 0);

    /* ── scenario 4: seat-time dnzinv send failure must reclaim the dnsnet
     * Peer. FD stability alone is not enough: a leaked used-slot would
     * route later announce/AE through a place-reused SConn. */
    {
        char dir4[] = "/tmp/serve-gossip4-XXXXXX";
        if (!mkdtemp(dir4)) { CHECK(0, "mkdtemp dnzinv-sendfail"); }
        else {
            struct seed seed;
            pthread_t th;
            CHECK(start_seed(&seed, &th, dir4), "idx_serve+dnsnet listen (sendfail)");
            CHECK(dnsnet_peers() == 0, "peer table empty before fail-seat");
#ifdef IDX_SERVE_TEST
            idx_serve_inject_fail_cmd = "dnzinv";
#endif
            int f = connect_loop(seed.port);
            CHECK(f >= 0, "fail-seat client F connect");
            Stash sf; memset(&sf, 0, sizeof sf);
            CHECK(f >= 0 && handshake(f, "/pepenet-desktop:0.2.3/", &sf),
                  "fail-seat client F marked handshake");
            if (f >= 0) send_dngetaddr(f);
            if (f >= 0) collect(f, &sf, 1500);
            usleep(80000);
            printf("info after dnzinv-sendfail peers=%d f_dnzinv=%d\n",
                   dnsnet_peers(), count_cmd(sf.o, sf.n, "dnzinv"));
            CHECK(dnsnet_peers() == 0,
                  "dnzinv sendfail reclaimed dnsnet peer (no leaked used slot)");
            if (f >= 0) close(f);

            int e = connect_loop(seed.port);
            CHECK(e >= 0, "engine E reuse-slot connect after fail-seat");
            Stash se; memset(&se, 0, sizeof se);
            CHECK(e >= 0 && handshake(e, "/pepenet-desktop:0.2.3/", &se),
                  "engine E marked handshake on reused accept slot");
            if (e >= 0) send_getblocks(e);
            usleep(50000);
            CHECK(dnsnet_peers() == 0, "engine reuse did not inherit a leaked seat");
            dnsnet_announce("zone");
            if (e >= 0) collect(e, &se, 1500);
            int e_inv = count_cmd(se.o, se.n, "dnzinv");
            printf("info reused-slot engine dnzinv=%d peers=%d\n", e_inv, dnsnet_peers());
            CHECK(e_inv == 0, "engine reused slot did not receive leaked/announced dnzinv");
            CHECK(dnsnet_peers() == 0, "announce did not resurrect a leaked peer");

            int ov = connect_loop(seed.port);
            CHECK(ov >= 0, "overlay O connect after fail-seat reuse");
            Stash so; memset(&so, 0, sizeof so);
            CHECK(ov >= 0 && handshake(ov, "/pepenet-desktop:0.2.3/", &so),
                  "overlay O marked handshake");
            if (ov >= 0) send_dngetaddr(ov);
            if (ov >= 0) collect(ov, &so, 1500);
            int o_inv = count_cmd(so.o, so.n, "dnzinv");
            printf("info overlay O after fail-seat dnzinv=%d peers=%d\n",
                   o_inv, dnsnet_peers());
            CHECK(o_inv > 0, "later overlay still receives dnzinv after fail-seat");
            CHECK(dnsnet_peers() == 1, "only the live overlay occupies the peer table");
            if (e >= 0) { collect(e, &se, 400); }
            CHECK(count_cmd(se.o, se.n, "dnzinv") == 0,
                  "engine still has no dnzinv after later overlay seated");
            if (e >= 0) close(e);
            if (ov >= 0) close(ov);
            usleep(80000);
            CHECK(dnsnet_peers() == 0, "peer table reclaimed after overlay disconnect");
            stop_seed(&seed, &th);
            char rm[700]; snprintf(rm, sizeof rm, "rm -rf -- %s", dir4); system(rm);
        }
    }

    int fds1 = fd_count();
    long rss1 = rss_kb();
    printf("info handles_after fd=%d rss_kb=%ld d_fd=%d d_rss=%ld\n",
           fds1, rss1, fds1 - fds0, rss1 - rss0);
    CHECK(fds1 - fds0 < 16, "fd count did not leak seats/handles");
    CHECK(rss1 < 0 || rss0 < 0 || rss1 - rss0 < 65536,
          "rss did not jump unbounded across fixtures");

    sp_state_close(st);
    char rm[700]; snprintf(rm, sizeof rm, "rm -rf -- %s", dir); system(rm);
    if (g_fail) printf("test_serve_gossip: FAILED\n");
    else printf("test_serve_gossip: all passed (isolated seating regression only)\n");
    return g_fail ? 1 : 0;
}
