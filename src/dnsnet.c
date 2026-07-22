// dnsnet.c — the embedded dns plane (see dnsnet.h). Modeled on dnsd.c's main:
// the net thread owns the write store + gossip, the resolver thread owns its
// own read handles, the UI thread gets mutex-guarded snapshots + a queue.
//
// Zones are anchor-ordered per-key LWW state (dnet_mesh sp_state): a record op
// is signed over a recent block-header hash, highest anchor wins per
// (label,type), a delete leaves the outranking tombstone, `clear` voids the
// zone below its floor. 8 KB of held ops per name (DNS_BUDGET); no store TTL —
// eviction is the lease-lapse sweep.
#include "dnsnet.h"
#include "appconf.h"
#include "wallet.h"
#include "zonekey.h"        // ZK (hot zone key) + zonekey_cert (delegation cert)

#include "dns_state.h"      // pepenet-dns: publish/zone/digest/sweep + DNS_BUDGET
#include "dns_chain.h"      // the lease-gated chain oracle
#include "dns_net.h"        // zone gossip over the chain wire
#include "dnsd_core.h"      // the extracted resolver
#include "indexer.h"        // idx_serve + IdxMeshHooks (the chain-wire transport)
#include "db.h"             // idx_db_open / idx_db_peers_agent (discovered pepenet peers)
#include "pepenet/view.h"   // test-mode ownership (PEPENET_DNS_TEST)
#include "pepenet/crypto.h"

#include <libgen.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#define PUB_CAP 16

typedef struct {
    char     name[64];
    zone_rec rec;
    int      clear;                 // a whole-zone clear (rec ignored)
} PubReq;

static struct {
    // config (dnsnet_boot)
    char coin[16];
    char chain_db[512], store_db[512], conf[512];
    struct { char host[80]; uint16_t port; } peers[8];
    int      n_peers;
    uint16_t listen;
    int      dns_port;
    // offline harness (PEPENET_DNS_TEST=<names-file>:<tip>)
    int      test;
    char     test_names[512];
    uint32_t test_tip;

    // threads
    pthread_t net_th, res_th;
    volatile int stop;
    int started, running, res_running;

    // net thread's handles (its thread + the mesh tick only)
    SpState      *st;
    DnsChain     *ch;
    SpView       *tvw;              // test-mode ownership view
    SpChainOracle orc;
    DnsdCore core;                  // resolver thread's core (its thread only)
    DnsChain *res_ch;
    SpView   *res_tvw;
#ifdef _WIN32
    DnsdCore  core53;               // the OS-resolver-path twin on :53 (NRPT
    DnsChain *res_ch53;             // cannot carry a port); resolver thread only
    SpView   *res_tvw53;
#endif

    // UI ⇄ net thread
    pthread_mutex_t mu;
    PubReq   q[PUB_CAP];
    int      nq;
    int      peers_up;
    int64_t  zones, records;
    char     last_err[128], last_pub[160];

    // UI-thread zone reads (own read handle, opened lazily)
    SpState *ui_st;
} g = { .mu = PTHREAD_MUTEX_INITIALIZER, .dns_port = APP_DNS_PORT };

// ── test-mode oracle (PEPENET_DNS_TEST) ───────────────────────────────────────
// ownership from view.c's test table; headers are a deterministic fake so the
// publish→admit loop closes offline (both sides derive the same hash).
static int t_owner(void *u, const char *name, uint8_t owner[20]) {
    return sp_view_owner_now((SpView *)u, name, owner);
}
static int t_header(void *u, uint32_t height, uint8_t out[32]) {
    (void)u;
    if (height > g.test_tip) return 0;
    uint8_t seed[8] = { 't','s','t',0, (uint8_t)height, (uint8_t)(height >> 8),
                        (uint8_t)(height >> 16), (uint8_t)(height >> 24) };
    sp_sha256(seed, sizeof seed, out);
    return 1;
}
static uint32_t t_tip(void *u) { (void)u; return g.test_tip; }

// open the oracle pair for one thread: chain mode → DnsChain, test mode → view
static int oracle_open(DnsChain **ch, SpView **tvw, SpChainOracle *orc) {
    if (g.test) {
        *tvw = sp_view_open_test(g.test_names, g.test_tip);
        if (!*tvw) return 0;
        orc->u = *tvw; orc->owner_now = t_owner; orc->header_at = t_header; orc->tip = t_tip;
        return 1;
    }
    *ch = dns_chain_open(g.chain_db);
    if (!*ch) return 0;
    *orc = dns_chain_oracle(*ch);
    return 1;
}
static void oracle_close(DnsChain *ch, SpView *tvw) {
    if (ch) dns_chain_close(ch);
    if (tvw) sp_view_close(tvw);
}

// ── config ────────────────────────────────────────────────────────────────────
static void conf_write_default(const char *path) {
    FILE *f = fopen(path, "wx");        // never clobber an existing conf
    if (!f) return;
    fprintf(f,
        "# " APP_NAME " — the dns plane (zone records over the chain wire)\n"
        "# Firehose mirror by construction: bounded at 8 KB of held records per\n"
        "# name (edits replace, deletes tombstone, records live until the name's\n"
        "# lease lapses — no store TTL). Peers come from the chain crawl's\n"
        "# \"" IDX_DNET_MARK "\" set; add `peer=host:port` to pin a direct one.\n"
        "#\n"
        "# The node listens on the coin's chain port by default, so a crawling\n"
        "# peer discovers it — reaching it is up to you (port-forward / DMZ the\n"
        "# port). Set `listen=0` for dial-only (NAT'd, outbound gossip only),\n"
        "# or `listen=<port>` to override.\n"
        "#\n"
        "# local resolver port (scoped to " APP_DOT_TLD "; point "
        "/etc/resolver/" APP_TLD " here)\n"
        "dns_port=" APP_DNS_PORT_S "\n");
    fclose(f);
}

static void add_peer(const char *hp) {
    if (g.n_peers >= 8) return;
    const char *colon = strrchr(hp, ':');
    if (!colon || colon == hp) return;
    size_t hl = (size_t)(colon - hp);
    if (hl >= sizeof g.peers[0].host) return;
    memcpy(g.peers[g.n_peers].host, hp, hl);
    g.peers[g.n_peers].host[hl] = 0;
    g.peers[g.n_peers].port = (uint16_t)atoi(colon + 1);
    if (!g.peers[g.n_peers].port) return;
    for (int i = 0; i < g.n_peers; i++)          // dupes: conf + discovered overlap
        if (g.peers[i].port == g.peers[g.n_peers].port &&
            !strcmp(g.peers[i].host, g.peers[g.n_peers].host)) return;
    g.n_peers++;
}

// crawl-discovered pepenet candidates land here (dnsnet.h), post-boot pre-start
void dnsnet_add_peer(const char *hostport) {
    int before = g.n_peers;
    add_peer(hostport);
    if (g.n_peers > before)
        fprintf(stderr, "dnsnet: mesh candidate %s (discovered)\n", hostport);
}

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t')) *--e = 0;
    return s;
}

static void conf_read(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[600];
    while (fgets(line, sizeof line, f)) {
        char *s = trim(line);
        if (!*s || *s == '#') continue;
        char *eq = strchr(s, '=');
        if (!eq) continue;
        *eq = 0;
        char *k = trim(s), *v = trim(eq + 1);
        if (!strcmp(k, "peer")) add_peer(v);
        else if (!strcmp(k, "listen")) g.listen = (uint16_t)atoi(v);
        else if (!strcmp(k, "dns_port")) g.dns_port = atoi(v);
    }
    fclose(f);
}

int dnsnet_boot(const char *coin, const char *chain_dbpath) {
    snprintf(g.coin, sizeof g.coin, "%s", coin);
    snprintf(g.chain_db, sizeof g.chain_db, "%s", chain_dbpath);
    /* listen by default on the coin's chain port — a node is inbound-reachable
     * (crawl-discoverable) out of the box; reaching it is the operator's job
     * (port-forward / DMZ). conf `listen=0` or PEPENET_DNS_LISTEN=0 opts out. */
    g.listen = idx_coin_port(coin);
    char dbdup[512];
    snprintf(dbdup, sizeof dbdup, "%s", chain_dbpath);
    const char *dir = dirname(dbdup);
    snprintf(g.store_db, sizeof g.store_db, "%s/dns-%s.db", dir, coin);
    snprintf(g.conf, sizeof g.conf, "%s/dns-%s.conf", dir, coin);

    conf_write_default(g.conf);
    conf_read(g.conf);

    const char *env;
    if ((env = getenv("PEPENET_DNS_PEER")) != NULL) { g.n_peers = 0; add_peer(env); }
    if ((env = getenv("PEPENET_DNS_LISTEN")) != NULL) g.listen = (uint16_t)atoi(env);
    if ((env = getenv("PEPENET_DNS_PORT")) != NULL) g.dns_port = atoi(env);
    if ((env = getenv("PEPENET_DNS_TEST")) != NULL) {
        const char *colon = strrchr(env, ':');
        if (colon && colon != env) {
            snprintf(g.test_names, sizeof g.test_names, "%.*s", (int)(colon - env), env);
            g.test_tip = (uint32_t)strtoul(colon + 1, NULL, 10);
            g.test = 1;
        }
    }
    return 1;
}

int dnsnet_test_view(void) { return g.test; }
const char *dnsnet_store_path(void) { return g.store_db; }
const char *dnsnet_chain_path(void) { return g.chain_db; }

// ── net thread ────────────────────────────────────────────────────────────────
// drain the UI's publish queue: build each record as an anchor-signed op and
// admit it locally (then announce), exactly dnsd's ctl path. The record is
// signed by the HOT zone key (ZK) under a §2.2 delegation cert the wallet
// minted for this name; only if no cert is available (no wallet / mint failed)
// do we fall back to owner-signing with the wallet key directly.
static void drain_publishes(void) {
    for (;;) {
        pthread_mutex_lock(&g.mu);
        PubReq rq;
        int have = g.nq > 0;
        if (have) {
            rq = g.q[0];
            memmove(g.q, g.q + 1, (size_t)(g.nq - 1) * sizeof g.q[0]);
            g.nq--;
        }
        pthread_mutex_unlock(&g.mu);
        if (!have) break;

        char out[160], err[128] = "";
        uint32_t tip = g.orc.tip(g.orc.u);
        uint8_t cert[256];
        int cl = ZK.ok ? zonekey_cert(rq.name, tip, cert, sizeof cert) : 0;
        const uint8_t *priv = cl > 0 ? ZK.seckey : WLT.seckey;
        const uint8_t *pub  = cl > 0 ? ZK.pub    : WLT.pub;
        int ct = cl > 0 ? SP_CERT_P2PKH : SP_CERT_NONE;

        int rc;
        char tn[12];
        if (rq.clear) {
            rc = dns_state_clear(g.st, &g.orc, rq.name, priv, pub,
                                 ct, cert, cl, err, sizeof err);
            if (rc == 1) snprintf(out, sizeof out, "CLEAR %s", rq.name);
            else snprintf(out, sizeof out, "CLEAR refused rc=%d: %s", rc, err);
        } else if (rq.rec.rdlen == 0) {
            rc = dns_state_del(g.st, &g.orc, rq.name, rq.rec.label, rq.rec.type,
                               priv, pub, ct, cert, cl, err, sizeof err);
            if (rc == 1)
                snprintf(out, sizeof out, "DEL %s %s",
                         rq.rec.label[0] ? rq.rec.label : "@",
                         zone_type_name(rq.rec.type, tn, sizeof tn));
            else snprintf(out, sizeof out, "DEL refused rc=%d: %s", rc, err);
        } else {
            rc = dns_state_put(g.st, &g.orc, rq.name, &rq.rec,
                               priv, pub, ct, cert, cl, err, sizeof err);
            if (rc == 1)
                snprintf(out, sizeof out, "PUT %s %s%s",
                         rq.rec.label[0] ? rq.rec.label : "@",
                         zone_type_name(rq.rec.type, tn, sizeof tn),
                         dns_rec_escape_hatchable(&rq.rec) ? "" : "  [>80B: gossip-only]");
            else
                snprintf(out, sizeof out, "PUT refused rc=%d: %s", rc, err);
        }
        if (rc == -2) snprintf(err, sizeof err, "chain not synced far enough to anchor");
        if (rc == 1) dnsnet_announce(rq.name);

        pthread_mutex_lock(&g.mu);
        snprintf(g.last_pub, sizeof g.last_pub, "%s", out);
        if (rc != 1) snprintf(g.last_err, sizeof g.last_err, "%s", err);
        pthread_mutex_unlock(&g.mu);
        if (rc != 1) fprintf(stderr, "dnsnet: publish refused: %s\n", err);
    }
}

// zones + records counters for the status bar
struct count_acc { int64_t zones, records; SpState *st; };
static int count_rows_cb(void *u, const uint8_t *key, int klen, int op,
                         uint32_t anchor, const uint8_t *blob, int blen) {
    (void)key; (void)klen; (void)op; (void)anchor; (void)blob; (void)blen;
    (*(int64_t *)u)++;
    return 1;
}
static int count_names_cb(void *u, const char *name) {
    struct count_acc *a = u;
    a->zones++;
    sp_state_iter(a->st, name, count_rows_cb, &a->records);
    return 1;
}

// ── chain-wire mesh: dnsnet (dns repo) rides idx_serve's connections ─────────
typedef void (*mesh_send_fn)(void *peer, const char *cmd, const uint8_t *pay, size_t n);

static void *mesh_up(void *ud, void *peer, mesh_send_fn send) {
    (void)ud;
    void *h = dnsnet_up(peer, (dnsnet_send_fn)send);
    if (h) { pthread_mutex_lock(&g.mu); g.peers_up++; pthread_mutex_unlock(&g.mu); }
    return h;
}
static void mesh_msg(void *ud, void *handle, const char *name, const uint8_t *pay, int n) {
    (void)ud;
    dnsnet_msg(handle, name, pay, n);
}
static void mesh_down(void *ud, void *handle) {
    (void)ud;
    dnsnet_down(handle);
    pthread_mutex_lock(&g.mu); if (g.peers_up > 0) g.peers_up--; pthread_mutex_unlock(&g.mu);
}
static void mesh_tick(void *ud) {
    (void)ud;
    // wall-clock-gated housekeeping (idx_serve calls this ~1 Hz): drain the UI
    // publish queue, service the gossip (hold queue + anti-entropy), refresh
    // the zone counters, sweep lapsed names daily (the TTL replacement).
    static time_t next_refresh = 0, next_sweep = 0;
    time_t now = time(NULL);
    drain_publishes();
    dnsnet_tick();
    if (now >= next_refresh) {
        next_refresh = now + 5;
        struct count_acc a = { 0, 0, g.st };
        sp_state_names(g.st, count_names_cb, &a);
        pthread_mutex_lock(&g.mu);
        g.zones = a.zones; g.records = a.records;
        pthread_mutex_unlock(&g.mu);
    }
    if (!next_sweep) next_sweep = now + 86400;
    if (now >= next_sweep) {
        next_sweep = now + 86400;
        int n = dns_state_sweep(g.st, &g.orc);
        if (n) fprintf(stderr, "dnsnet: sweep dropped %d lapsed name(s)\n", n);
    }
}

static void *net_main(void *arg) {
    (void)arg;
    // first boot: the engine may not have created/schema'd the chain db yet —
    // keep retrying (the oracle prepares against the names table) until it
    // appears or we are stopped, instead of dying and leaving the plane dark.
    while (!g.stop && !oracle_open(&g.ch, &g.tvw, &g.orc))
        for (int i = 0; i < 10 && !g.stop; i++) usleep(100000);
    if (g.stop) { g.running = 0; return NULL; }
    g.st = sp_state_open(g.store_db);
    if (!g.st) { oracle_close(g.ch, g.tvw); g.running = 0; return NULL; }
    dnsnet_init(g.st, g.orc, 0);

    // dial list: the seed node (chain port) + crawl-discovered IDX_DNET_MARK
    // peers. Default is dial-only (listen 0) — a NAT'd node gossips over its
    // outbound chain connections. Set `listen=<port>` (conf) or PEPENET_DNS_LISTEN
    // to accept inbound: the node then advertises the mark on the chain wire so
    // a peer's crawl classifies + dials it (requires the port be reachable/forwarded).
    // The list is deduped by RESOLVED identity: the seed's harvested addr-book
    // row (numeric ip, recorded at every sync handshake) IS the seed, and two
    // seats pointed at one machine spend the whole run dueling (dial →
    // duplicate-drop → backoff). The seed entry stays in hostname form — the
    // serve loop re-resolves it per dial, which is what tracks a DNS change —
    // so its numeric twins are dropped here instead. If resolution fails (no
    // network yet), sip stays empty, duplicates may seat, and idx_serve's
    // per-ip park discipline collapses them after the first connect.
    char dial[1024]; int dl = 0;
    dl += snprintf(dial + dl, sizeof dial - dl, "%s", APP_SEED_PEER);
    char shost[80]; uint16_t sport;                   // seed host / port split
    { snprintf(shost, sizeof shost, "%s", APP_SEED_PEER);
      char *c = strrchr(shost, ':');
      sport = idx_coin_port(g.coin);
      if (c && !strchr(c, ']')) { *c = 0; sport = (uint16_t)atoi(c + 1); } }
    char sip[64] = "";
    { struct addrinfo h, *res = NULL; memset(&h, 0, sizeof h);
      h.ai_family = AF_INET; h.ai_socktype = SOCK_STREAM;
      if (getaddrinfo(shost, NULL, &h, &res) == 0 && res) {
          inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr, sip, sizeof sip);
          freeaddrinfo(res);
      } }
    char seedaddr[96]; snprintf(seedaddr, sizeof seedaddr, "%s:%u", sip, sport);
    for (int i = 0; i < g.n_peers && dl < (int)sizeof dial - 96; i++) {
        if (!strcmp(g.peers[i].host, shost) ||
            (sip[0] && g.peers[i].port == sport && !strcmp(g.peers[i].host, sip))) continue;
        dl += snprintf(dial + dl, sizeof dial - dl, ",%s:%u", g.peers[i].host, g.peers[i].port);
    }
    { sqlite3 *cdb = idx_db_open(g.chain_db);
      if (cdb) {
          idx_db_peers_scrub(cdb);   // pre-fix hostname rows must not seed dials
          char dn[8][80]; int nd = idx_db_peers_agent(cdb, IDX_DNET_MARK, dn, 8);
          for (int i = 0; i < nd && dl < (int)sizeof dial - 84; i++) {
              if (sip[0] && !strcmp(dn[i], seedaddr)) continue;   // the seed again, by ip
              dl += snprintf(dial + dl, sizeof dial - dl, ",%s", dn[i]);
          }
          idx_db_close(cdb);
      } }

    IdxMeshHooks mesh = { mesh_up, mesh_msg, mesh_down, mesh_tick, NULL };
    if (g.listen)
        fprintf(stderr, "dnsnet: listening on chain port %u (inbound + crawl-discoverable)\n", g.listen);
    idx_serve(g.coin, g.chain_db, g.listen /* 0 = dial-only */, dial, &g.stop, &mesh);

    sp_state_close(g.st);
    oracle_close(g.ch, g.tvw);
    g.running = 0;
    return NULL;
}

// ── resolver thread ───────────────────────────────────────────────────────────
static void *res_main(void *arg) {
    (void)arg;
    DnsdCore *dc = &g.core;
    memset(dc, 0, sizeof *dc);
    dc->suffix = APP_TLD;
    dc->tls_redirect = 1;                       // steer DANE names at the proxy
    dc->tls_redirect_ip[0] = 127; dc->tls_redirect_ip[3] = 1;
    dc->ufd = dc->tfd = -1;

    while (!g.stop && !oracle_open(&g.res_ch, &g.res_tvw, &dc->oracle))
        for (int i = 0; i < 10 && !g.stop; i++) usleep(100000);
    if (g.stop) { g.res_running = 0; return NULL; }
    dc->st = sp_state_open(g.store_db);
    if (!dc->st) {
        oracle_close(g.res_ch, g.res_tvw);
        g.res_running = 0;
        return NULL;
    }

    if (dnsd_core_bind(dc, "127.0.0.1", g.dns_port) != 0) {
        sp_state_close(dc->st); oracle_close(g.res_ch, g.res_tvw);
        g.res_running = 0;
        return NULL;
    }
    fprintf(stderr, "dnsnet: resolver on 127.0.0.1:%d (.%s)\n", g.dns_port, dc->suffix);

    DnsdCore *dc53 = NULL;
#ifdef _WIN32
    // Windows' per-TLD DNS routing (NRPT) steers ".<tld>" at 127.0.0.1 but
    // cannot name a port — serve the OS resolver path on :53 too. Loopback
    // only, best-effort: a busy :53 (WSL/ICS/docker) just disables that path.
    if (g.dns_port != 53) {
        dc53 = &g.core53;
        memset(dc53, 0, sizeof *dc53);
        dc53->suffix = APP_TLD;
        dc53->tls_redirect = 1;
        dc53->tls_redirect_ip[0] = 127; dc53->tls_redirect_ip[3] = 1;
        dc53->ufd = dc53->tfd = -1;
        int up = oracle_open(&g.res_ch53, &g.res_tvw53, &dc53->oracle);
        if (up) {
            dc53->st = sp_state_open(g.store_db);
            up = dc53->st && dnsd_core_bind(dc53, "127.0.0.1", 53) == 0;
        }
        if (up)
            fprintf(stderr, "dnsnet: resolver also on 127.0.0.1:53 (the NRPT path)\n");
        else {
            if (dc53->st) { sp_state_close(dc53->st); dc53->st = NULL; }
            oracle_close(g.res_ch53, g.res_tvw53);
            g.res_ch53 = NULL; g.res_tvw53 = NULL;
            fprintf(stderr, "dnsnet: 127.0.0.1:53 unavailable — system "
                            APP_DOT_TLD " resolution off until it frees up\n");
            dc53 = NULL;
        }
    }
#endif

    while (!g.stop) {
        dnsd_core_poll(dc, dc53 ? 200 : 500);
        if (dc53) dnsd_core_poll(dc53, 200);
    }

#ifdef _WIN32
    if (dc53) {
        dnsd_core_close(dc53);
        sp_state_close(dc53->st);
        oracle_close(g.res_ch53, g.res_tvw53);
    }
#endif
    dnsd_core_close(dc);
    sp_state_close(dc->st);
    oracle_close(g.res_ch, g.res_tvw);
    g.res_running = 0;
    return NULL;
}

// ── lifecycle (UI thread) ─────────────────────────────────────────────────────
int dnsnet_start(void) {
    if (g.started) return 1;
    // create/repair the store HERE, before either thread or the UI reader can
    // touch the path (a crashed first run leaves a 0-byte db)
    SpState *st = sp_state_open(g.store_db);
    if (!st) return 0;
    sp_state_close(st);
    g.stop = 0;
    g.started = g.running = g.res_running = 1;
    if (pthread_create(&g.net_th, NULL, net_main, NULL) != 0) {
        g.started = g.running = g.res_running = 0;
        return 0;
    }
    if (pthread_create(&g.res_th, NULL, res_main, NULL) != 0) {
        g.stop = 1;
        pthread_join(g.net_th, NULL);
        g.started = g.running = g.res_running = 0;
        return 0;
    }
    return 1;
}

void dnsnet_stop(void) {
    if (!g.started) return;
    g.stop = 1;
    pthread_join(g.net_th, NULL);
    pthread_join(g.res_th, NULL);
    if (g.ui_st) { sp_state_close(g.ui_st); g.ui_st = NULL; }
    g.started = 0;
}

// ── UI-thread surface ─────────────────────────────────────────────────────────
void dnsnet_status(DnsStatus *out) {
    memset(out, 0, sizeof *out);
    out->running = g.running;
    out->resolver_running = g.res_running;
    out->resolver_port = g.dns_port;
    pthread_mutex_lock(&g.mu);
    out->peers = g.peers_up;
    out->zones_held = g.zones;
    out->records_held = g.records;
    snprintf(out->last_err, sizeof out->last_err, "%s", g.last_err);
    snprintf(out->last_pub, sizeof out->last_pub, "%s", g.last_pub);
    pthread_mutex_unlock(&g.mu);
}

int dnsnet_publish(const char *name, const zone_rec *rec) {
    if (!g.running || !name || !*name || !rec) return 0;
    pthread_mutex_lock(&g.mu);
    int ok = g.nq < PUB_CAP;
    if (ok) {
        PubReq *q = &g.q[g.nq++];
        snprintf(q->name, sizeof q->name, "%s", name);
        q->rec = *rec;
        q->clear = 0;
    }
    pthread_mutex_unlock(&g.mu);
    return ok;
}

int dnsnet_publish_clear(const char *name) {
    if (!g.running || !name || !*name) return 0;
    pthread_mutex_lock(&g.mu);
    int ok = g.nq < PUB_CAP;
    if (ok) {
        PubReq *q = &g.q[g.nq++];
        snprintf(q->name, sizeof q->name, "%s", name);
        memset(&q->rec, 0, sizeof q->rec);
        q->clear = 1;
    }
    pthread_mutex_unlock(&g.mu);
    return ok;
}

int dnsnet_publish_tlsa(const char *host, const uint8_t spki[32]) {
    if (!host || !*host || !spki) return 0;
    // host = apex ("gm") or dotted sub ("shop.gm"): apex is the last label, the
    // TLSA label is "_443._tcp" at the apex or "_443._tcp.<sub>" for a sub.
    const char *dot = strrchr(host, '.');
    const char *apex = dot ? dot + 1 : host;
    char label[96];
    if (dot) snprintf(label, sizeof label, "_443._tcp.%.*s", (int)(dot - host), host);
    else     snprintf(label, sizeof label, "_443._tcp");
    char rdata[80];
    size_t o = (size_t)snprintf(rdata, sizeof rdata, "3 1 1 ");
    for (int i = 0; i < 32; i++) o += (size_t)snprintf(rdata + o, sizeof rdata - o, "%02x", spki[i]);
    zone_rec rec;
    if (zone_build_rec(label, "TLSA", 3600, rdata, &rec) != 0) return 0;
    return dnsnet_publish(apex, &rec);
}

int dnsnet_unpublish_tlsa(const char *host) {
    if (!host || !*host) return 0;
    // same label derivation as publish; NULL rdata = rdlen 0 = the signed
    // delete tombstone that outranks every replay of the old pin
    const char *dot = strrchr(host, '.');
    const char *apex = dot ? dot + 1 : host;
    char label[96];
    if (dot) snprintf(label, sizeof label, "_443._tcp.%.*s", (int)(dot - host), host);
    else     snprintf(label, sizeof label, "_443._tcp");
    zone_rec rec;
    if (zone_build_rec(label, "TLSA", 3600, NULL, &rec) != 0) return 0;
    return dnsnet_publish(apex, &rec);
}

int dnsnet_zone(const char *name, zone *z) {
    if (!g.started || !name || !*name) return -1;
    if (!g.ui_st) g.ui_st = sp_state_open(g.store_db);   // lazy read connection
    if (!g.ui_st) return -1;
    return dns_state_zone(g.ui_st, name, z);
}

int64_t dnsnet_zone_bytes(const char *name) {
    if (!g.started || !name || !*name) return -1;
    if (!g.ui_st) g.ui_st = sp_state_open(g.store_db);
    if (!g.ui_st) return -1;
    return sp_state_sum(g.ui_st, name);
}
