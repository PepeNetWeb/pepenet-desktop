/* dnsd.c — the pepenet-dns node: a first-class CHAIN peer that gossips DNS.
 *
 * A pepenet node speaks the host chain's P2P protocol on the chain port; the DNS
 * mesh rides that same wire as extra dn* commands (peer-discovery slice 3) — no
 * separate mesh port. Three threads:
 *
 *   • sync thread — indexer_main("sync") in a loop; keeps the ownership db
 *     (pep.db) and the NODE_NETWORK_LIMITED serve window (serve-<coin>.db)
 *     fresh by syncing the chain outbound. --no-sync if an external indexer
 *     already feeds the db on this box.
 *   • net thread  — dns_net + idx_serve: listen on the chain port (a public
 *     seed) and/or dial --peer chain peers, and gossip zones as dnz* commands
 *     over every "/pepenet-" connection. Owns the write store; services the
 *     ctl socket + startup publish + the resumable expiry sweep in the mesh tick.
 *   • main thread — the UDP/TCP DNS resolver (dnsd_core), separate read handles
 *     (sqlite WAL makes concurrent read-while-write safe).
 *
 * A node with --key/--name is an owner publishing a zone; a node without just
 * mirrors everything gossiped and resolves what it pulls from peers. Records
 * ride the anchor-ordered LWW store (pepenet/state.h): every op is signed over
 * a recent block-header hash, highest anchor wins per (label, type), a `del`
 * leaves the outranking tombstone, `clear` voids the whole zone below its
 * anchor. Per-name budget DNS_BUDGET; no store TTL — records live until
 * superseded, cleared, or the name's lease lapses (the sweep). */
#include "dns_state.h"
#include "dns_chain.h"
#include "dns_net.h"
#include "dnsd_core.h"
#include "dns_wire.h"
#include "zone.h"
#include "indexer.h"        /* idx_serve + IdxMeshHooks + indexer_main + idx_sync_* */
#include "db.h"             /* idx_db_open / idx_db_peers_agent (discovered peers) */
#include "pepenet/crypto.h" /* sp_pubkey, sp_name_valid */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

/* L6/L7 transport hooks from the indexer's serve layer. Declared weak here so
 * dnsd still builds and links against an indexer that predates them; then the
 * L6 disconnect and the L7 drain gate are simply off (everything else works). */
size_t idx_serve_peer_pending(void *peer) __attribute__((weak));
void   idx_serve_peer_kick(void *peer, const char *why) __attribute__((weak));
int    idx_serve_peer_exempt(void *peer) __attribute__((weak));

#define PASS_PAUSE_S 20        /* pep blocks ~1/min; a pass ends when caught up */

static volatile int g_stop = 0;
static void on_sig(int s) { (void)s; g_stop = 1; idx_sync_stop = 1; }

/* publishing identity (owner) + zone */
static uint8_t g_priv[32], g_pub[33];
static int     g_have_key = 0;
static char    g_apex[64];
static zone    g_zone;
static int     g_have_zone = 0;
static int     g_verbose = 0;

/* the resolver core (main thread only) */
static DnsdCore g_core = { .suffix = "pepe", .ufd = -1, .tfd = -1 };
static DnsChain *g_core_ch;                 /* the resolver's own oracle handle */

/* the net thread's write store + oracle (its thread + the mesh tick only) */
static SpState      *g_st;
static DnsChain     *g_ch;
static SpChainOracle g_orc;

/* control socket (owner-node live updates; serviced on the net thread's tick) */
static int         g_ctl_fd = -1;
static const char *g_ctl_path = NULL;

/* ── startup publish (net thread, via mesh tick) ─────────────────────────────── */
static void publish_zone_once(void) {
    int ok = 0;
    char err[128];
    for (int i = 0; i < g_zone.n; i++) {
        int rc = dns_state_put(g_st, &g_orc, g_apex, &g_zone.recs[i],
                               g_priv, g_pub, SP_CERT_NONE, NULL, 0, err, sizeof err);
        if (rc == 1) ok++;
        if (g_verbose)
            fprintf(stderr, "  publish %s/%u rc=%d %s\n",
                    g_zone.recs[i].label[0] ? g_zone.recs[i].label : "@",
                    g_zone.recs[i].type, rc, rc == 1 ? "ok" : err);
    }
    if (ok) dnsnet_announce(g_apex);
    fprintf(stderr, "dnsd: published %d/%d records for %s\n", ok, g_zone.n, g_apex);
}

/* ── control socket: live PUT/DEL/CLEAR/LIST/USAGE from dns-cli ──────────────── */
static void ctl_dispatch(char *req, char *resp, int rmax) {
    req[strcspn(req, "\r\n")] = '\0';
    char cmd[16] = {0};
    if (sscanf(req, "%15s", cmd) != 1) { snprintf(resp, rmax, "-ERR empty\n"); return; }

    if (!strcasecmp(cmd, "LIST")) {
        if (!g_apex[0]) { snprintf(resp, rmax, "-ERR node has no --name\n"); return; }
        zone z; dns_state_zone(g_st, g_apex, &z);
        int o = snprintf(resp, rmax, "+OK %s (%d records)\n", g_apex, z.n);
        for (int i = 0; i < z.n && o < rmax - 256; i++) {
            zone_rec *r = &z.recs[i];
            char tn[12];
            o += snprintf(resp + o, rmax - o, "  %-12s %-6s %6u  ",
                          r->label[0] ? r->label : "@", zone_type_name(r->type, tn, sizeof tn), r->ttl);
            for (int j = 0; j < r->rdlen && o < rmax - 4; j++)
                o += snprintf(resp + o, rmax - o, "%02x", r->rdata[j]);
            o += snprintf(resp + o, rmax - o, "\n");
        }
        return;
    }
    if (!strcasecmp(cmd, "USAGE")) {
        if (!g_apex[0]) { snprintf(resp, rmax, "-ERR node has no --name\n"); return; }
        snprintf(resp, rmax, "+OK %s %lld/%d bytes  floor=%u\n", g_apex,
                 (long long)sp_state_sum(g_st, g_apex), DNS_BUDGET,
                 sp_state_floor(g_st, g_apex));
        return;
    }

    int isdel = !strcasecmp(cmd, "DEL"), isput = !strcasecmp(cmd, "PUT");
    int isclear = !strcasecmp(cmd, "CLEAR");
    if (isput || isdel || isclear) {
        if (!g_have_key || !g_apex[0]) { snprintf(resp, rmax, "-ERR node holds no --key/--name; cannot publish\n"); return; }
        char err[128];
        int rc;
        char what[96];
        if (isclear) {
            rc = dns_state_clear(g_st, &g_orc, g_apex, g_priv, g_pub,
                                 SP_CERT_NONE, NULL, 0, err, sizeof err);
            snprintf(what, sizeof what, "CLEAR");
        } else if (isdel) {
            char label[64], type_s[16];
            if (sscanf(req, "%*s %63s %15s", label, type_s) != 2) { snprintf(resp, rmax, "-ERR usage: DEL <label> <type>\n"); return; }
            zone_rec rec;
            if (zone_build_rec(label, type_s, 0, "", &rec) != 0) { snprintf(resp, rmax, "-ERR unknown type %s\n", type_s); return; }
            rc = dns_state_del(g_st, &g_orc, g_apex, rec.label, rec.type,
                               g_priv, g_pub, SP_CERT_NONE, NULL, 0, err, sizeof err);
            snprintf(what, sizeof what, "DEL %s %s", label, type_s);
        } else {
            char label[64], type_s[16]; unsigned ttl = 0; int consumed = 0;
            if (sscanf(req, "%*s %63s %15s %u %n", label, type_s, &ttl, &consumed) < 3) {
                snprintf(resp, rmax, "-ERR usage: PUT <label> <type> <ttl> <rdata...>\n"); return;
            }
            zone_rec rec;
            if (zone_build_rec(label, type_s, ttl, req + consumed, &rec) != 0) {
                snprintf(resp, rmax, "-ERR bad type/rdata for %s\n", type_s); return;
            }
            rc = dns_state_put(g_st, &g_orc, g_apex, &rec,
                               g_priv, g_pub, SP_CERT_NONE, NULL, 0, err, sizeof err);
            snprintf(what, sizeof what, "PUT %s %s", label, type_s);
        }
        if (rc == 1) {
            dnsnet_announce(g_apex);
            snprintf(resp, rmax, "+OK %s  (%lld/%d bytes)\n", what,
                     (long long)sp_state_sum(g_st, g_apex), DNS_BUDGET);
        } else if (rc == -2) {
            snprintf(resp, rmax, "-ERR chain not synced far enough to anchor (retry shortly)\n");
        } else {
            snprintf(resp, rmax, "-ERR rc=%d: %s\n", rc, err);
        }
        return;
    }
    snprintf(resp, rmax, "-ERR unknown command '%s' (PUT|DEL|CLEAR|LIST|USAGE)\n", cmd);
}

static void service_ctl(void) {
    if (g_ctl_fd < 0) return;
    int cfd;
    while ((cfd = accept(g_ctl_fd, NULL, NULL)) >= 0) {
        struct timeval tv = { 2, 0 };
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        char req[2048]; int rl = 0;
        while (rl < (int)sizeof req - 1) {
            ssize_t n = read(cfd, req + rl, sizeof req - 1 - (size_t)rl);
            if (n <= 0) break;
            rl += (int)n;
            if (memchr(req, '\n', (size_t)rl)) break;
        }
        req[rl] = '\0';
        char resp[8192];
        ctl_dispatch(req, resp, sizeof resp);
        (void)write(cfd, resp, strlen(resp));
        close(cfd);
    }
}

/* ── chain-wire mesh: dnsnet rides the P2P connections idx_serve manages ─────── */
typedef void (*mesh_send_fn)(void *peer, const char *cmd, const uint8_t *pay, size_t n);

static void *mesh_up(void *ud, void *peer, mesh_send_fn send) {
    (void)ud;
    return dnsnet_up(peer, (dnsnet_send_fn)send);
}
static void mesh_msg(void *ud, void *handle, const char *name, const uint8_t *pay, int n) {
    (void)ud;
    dnsnet_msg(handle, name, pay, n);
}
static void mesh_down(void *ud, void *handle) {
    (void)ud;
    dnsnet_down(handle);
}
/* P10: a name whose current ownership epoch is >= ~30 days old (1-minute
 * blocks) is senior: under backlog its announces and pulls go first. A name
 * with no live owner is never senior; an owned name with no epochs row has
 * been owned since before the projection began, so it counts as senior. */
#define SENIOR_BLOCKS (30 * 1440)
static int name_senior(const char *name) {
    uint8_t owner[20];
    if (!g_orc.owner_now(g_orc.u, name, owner)) return 0;
    int64_t start = dns_chain_epoch_start(g_ch, name);
    if (start < 0) return 1;
    uint32_t tip = g_orc.tip(g_orc.u);
    return (int64_t)tip - start >= SENIOR_BLOCKS;
}

/* P11: the expiry sweep runs as a resumable step every SWEEP_EVERY_S, each
 * step looking at up to SWEEP_STEP names after where the last one stopped. */
#ifndef SWEEP_EVERY_S
#define SWEEP_EVERY_S 600
#endif
#ifndef SWEEP_STEP
#define SWEEP_STEP 4096
#endif
static void mesh_tick(void *ud) {
    (void)ud;
    static int published = 0;
    static time_t next_sweep = 0;
    static char sweep_cursor[SP_NAME_MAX + 1];
    if (!published && g_have_zone && g_have_key) { publish_zone_once(); published = 1; }
    service_ctl();
    dnsnet_tick();
    /* expiry sweep: a name whose lease lapsed on chain takes its records with
       it — this replaces the old store TTL entirely. */
    time_t now = time(NULL);
    if (!next_sweep) next_sweep = now + SWEEP_EVERY_S;
    if (now >= next_sweep) {
        next_sweep = now + SWEEP_EVERY_S;
        int seen = 0;
        int n = dns_state_sweep_step(g_st, &g_orc, sweep_cursor, SWEEP_STEP, &seen);
        if (n && g_verbose) fprintf(stderr, "dnsd: sweep dropped %d lapsed name(s) of %d examined\n", n, seen);
    }
}

/* ── net thread (mesh + chain-wire serve) ────────────────────────────────────── */
struct netargs { const char *coin, *db, *store, *dial; uint16_t listen; };
static void *net_main(void *a) {
    struct netargs *na = a;
    g_ch = dns_chain_open(na->db);
    g_st = sp_state_open(na->store);
    if (!g_ch || !g_st) { fprintf(stderr, "dnsd: cannot open db/store\n"); g_stop = 1; return NULL; }
    g_orc = dns_chain_oracle(g_ch);
    dnsnet_init(g_st, g_orc, g_verbose);
    dnsnet_set_seniority(name_senior);        /* kept for API compat; L2 lanes replace P10 */
    if (idx_serve_peer_pending && idx_serve_peer_kick && idx_serve_peer_exempt)   /* L6/L7 (weak, see top) */
        dnsnet_set_transport(idx_serve_peer_pending, idx_serve_peer_kick, idx_serve_peer_exempt);

    IdxMeshHooks mesh = { mesh_up, mesh_msg, mesh_down, mesh_tick, NULL, serve_conn_misbehave };
    dnsnet_set_misbehave(serve_conn_misbehave);
    idx_serve(na->coin, na->db, na->listen, na->dial, &g_stop, &mesh);

    sp_state_close(g_st); dns_chain_close(g_ch);
    return NULL;
}

/* ── sync thread (keeps the ownership db + serve window fresh) ────────────────── */
struct syncargs { const char *coin, *db, *peer; };
static void *sync_main(void *a) {
    struct syncargs *sa = a;
    /* argv[4] = the sync peer; "auto" (default) lets the ladder use cached
       last-good peers then the chain's DNS seeds. Same code the headless
       indexerd and the desktop engine run. */
    char *argv[5] = { "dnsd", "sync", (char *)sa->coin, (char *)sa->db, (char *)sa->peer };
    while (!g_stop) {
        idx_sync_stop = 0;
        indexer_main(5, argv);
        for (int i = 0; i < PASS_PAUSE_S * 10 && !g_stop; i++) usleep(100000);
    }
    return NULL;
}

/* ── key / args ──────────────────────────────────────────────────────────────── */
static int hex2bin(const char *h, uint8_t *o, int n) {
    for (int i = 0; i < n; i++) { unsigned v; if (sscanf(h + 2 * i, "%2x", &v) != 1) return 0; o[i] = (uint8_t)v; }
    return 1;
}
/* load a 32-byte priv from a hex string, or from a wallet file's `seckey=` line */
static int load_key(const char *arg, uint8_t priv[32]) {
    if (strlen(arg) == 64 && hex2bin(arg, priv, 32)) return 1;
    FILE *f = fopen(arg, "r"); if (!f) return 0;
    char line[256]; int ok = 0;
    while (fgets(line, sizeof line, f))
        if (strncmp(line, "seckey=", 7) == 0 && hex2bin(line + 7, priv, 32)) { ok = 1; break; }
    fclose(f); return ok;
}

static int usage(const char *p) {
    fprintf(stderr,
        "usage: %s --db <indexer.db> --store <zones.db> [options]\n"
        "  --db <path>        indexer sqlite (ownership + chain)     [required]\n"
        "  --store <path>     this node's zone store                 [required]\n"
        "  --coin <id>        host chain id                          [default pep]\n"
        "  --listen <port>    CHAIN serve port (0 = dial-only)       [default 0]\n"
        "                     a public seed passes its chain port (pep 33874)\n"
        "  --peer host:port   a chain peer to dial for the mesh (repeatable)\n"
        "                     default pep: pepenet.shibpost.com:33874 +\n"
        "                     net.pepecoin.services:33874; doge:\n"
        "                     dogenet.shibpost.com:22556 +\n"
        "                     seed.dogecoin.services:22556\n"
        "  --sync-peer <ip>   pin the chain-sync peer                [default auto]\n"
        "  --no-sync          do not self-sync (an external indexer feeds --db)\n"
        "  --dns-addr <ip>    UDP/TCP DNS listen addr                [127.0.0.1]\n"
        "  --dns-port <n>     UDP/TCP DNS listen port                [5353]\n"
        "  --suffix <tld>     hostchain suffix (no dot)              [from --coin]\n"
        "  --tls-redirect <ip> answer A=<ip> for DANE names (steer to local proxy)\n"
        "  --key <file|hex>   owner key — enables publishing --zone + live PUT/DEL\n"
        "  --name <apex>      flat pepenet name (§3.1: [a-z0-9-], 1..32)\n"
        "  --zone <file>      zone file to publish at startup\n"
        "  --ctl <path>       unix control socket for dns-cli (live updates)\n"
        "  --uplink-mbit <n>  L7 Pi profile: cap dn* gossip peers at n/0.52 [no cap]\n"
        "  --relay-credit-blocks <n>  L2: one relay credit per n blocks per name [10]\n"
        "  -v                 verbose\n", p);
    return 2;
}

int main(int argc, char **argv) {
    const char *db = NULL, *store = NULL, *keyarg = NULL, *name = NULL, *zonef = NULL;
    const char *dns_addr = "127.0.0.1", *ctl_path = NULL, *coin = "pep", *sync_peer = "auto";
    int dns_port = 5353, do_sync = 1, suffix_set = 0;
    uint16_t chain_port = 0;
    char peers[16][96]; int n_peers = 0;

    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--db")       && i+1 < argc) db = argv[++i];
        else if (!strcmp(argv[i], "--store")    && i+1 < argc) store = argv[++i];
        else if (!strcmp(argv[i], "--coin")     && i+1 < argc) coin = argv[++i];
        else if (!strcmp(argv[i], "--listen")   && i+1 < argc) chain_port = (uint16_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--sync-peer")&& i+1 < argc) sync_peer = argv[++i];
        else if (!strcmp(argv[i], "--no-sync")) do_sync = 0;
        else if (!strcmp(argv[i], "--dns-addr") && i+1 < argc) dns_addr = argv[++i];
        else if (!strcmp(argv[i], "--dns-port") && i+1 < argc) dns_port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--suffix")   && i+1 < argc) {
            g_core.suffix = argv[++i];
            suffix_set = 1;
        }
        else if (!strcmp(argv[i], "--tls-redirect") && i+1 < argc) {
            if (inet_pton(AF_INET, argv[++i], g_core.tls_redirect_ip) != 1) {
                fprintf(stderr, "bad --tls-redirect ip '%s'\n", argv[i]); return 1;
            }
            g_core.tls_redirect = 1;
        }
        else if (!strcmp(argv[i], "--key")      && i+1 < argc) keyarg = argv[++i];
        else if (!strcmp(argv[i], "--name")     && i+1 < argc) name = argv[++i];
        else if (!strcmp(argv[i], "--zone")     && i+1 < argc) zonef = argv[++i];
        else if (!strcmp(argv[i], "--ctl")      && i+1 < argc) ctl_path = argv[++i];
        else if (!strcmp(argv[i], "--peer")     && i+1 < argc && n_peers < 16) {
            /* a chain peer host:port; the mesh dials it over the chain wire */
            if (!strrchr(argv[i+1], ':')) return usage(argv[0]);
            snprintf(peers[n_peers++], sizeof peers[0], "%s", argv[++i]);
        }
        else if (!strcmp(argv[i], "--uplink-mbit") && i+1 < argc) {
            double mb = atof(argv[++i]);
            if (mb <= 0) { fprintf(stderr, "bad --uplink-mbit '%s'\n", argv[i]); return 1; }
            dnsnet_set_peer_cap(dnsnet_peer_cap_for_uplink(mb));
        }
        else if (!strcmp(argv[i], "--relay-credit-blocks") && i+1 < argc) {
            int cb = atoi(argv[++i]);
            if (cb < 1 || cb > 1440) { fprintf(stderr, "bad --relay-credit-blocks '%s' (1..1440)\n", argv[i]); return 1; }
            dnsnet_set_credit_blocks(cb);
        }
        else if (!strcmp(argv[i], "-v")) g_verbose = 1;
        else return usage(argv[0]);
    }
    if (!db || !store) return usage(argv[0]);

    /* Overlay seeds ride the chain wire (idx_serve dial list). Omit --peer
       and a pep/doge node still finds the mesh; an explicit --peer replaces
       the default rather than appending. testnet/regtest stay silent. */
    if (n_peers == 0) {
        if (!strcmp(coin, "pep")) {
            snprintf(peers[n_peers++], sizeof peers[0], "pepenet.shibpost.com:33874");
            snprintf(peers[n_peers++], sizeof peers[0], "net.pepecoin.services:33874");
        } else if (!strcmp(coin, "doge")) {
            snprintf(peers[n_peers++], sizeof peers[0], "dogenet.shibpost.com:22556");
            snprintf(peers[n_peers++], sizeof peers[0], "seed.dogecoin.services:22556");
        }
    }
    /* --suffix wins. Otherwise the coin row names the suffix: pep → pepe,
     * doge → doge. An unknown coin keeps the compile-time "pepe" default. */
    if (!suffix_set) {
        if (!strcmp(coin, "doge")) g_core.suffix = "doge";
        else if (!strcmp(coin, "pep")) g_core.suffix = "pepe";
    }
    uint8_t onchain_magic[2] = { 0, 0 };
    idx_coin_onchain_magic(coin, onchain_magic);

    if (keyarg) {
        if (!load_key(keyarg, g_priv) || !sp_pubkey(g_priv, g_pub)) { fprintf(stderr, "bad --key\n"); return 1; }
        g_have_key = 1;
    }
    if (name) {
        if (!sp_name_valid(name, strlen(name))) {
            fprintf(stderr, "bad --name '%s': must be a §3.1 pepenet name "
                    "([a-z0-9-], 1..32, no lead/trail hyphen, no xn--)\n", name);
            return 1;
        }
        snprintf(g_apex, sizeof g_apex, "%s", name);
    }
    if (zonef) {
        if (!name) { fprintf(stderr, "--zone needs --name\n"); return 1; }
        if (zone_load(&g_zone, zonef, name) != 0) { fprintf(stderr, "cannot load zone %s\n", zonef); return 1; }
        g_have_zone = 1;
    }

    /* our P2P subver: the IDX_DNET_MARK prefix (indexer.h; per-deployment at
       build time, "/pepenet-" default) is the mesh's discovery mark — a
       crawler classifies this node as dns-aware by it (peer-discovery design).
       Set before either the sync or serve thread sends a version. */
    idx_sync_agent = IDX_DNET_MARK "dnsd:0.1/";

    /* the chain-wire dial list for the mesh: --peer args first, then the crawl's
       discovered "/pepenet-" peers from the ownership db's peers table. */
    char dial[1024]; int dl = 0; dial[0] = '\0';
    for (int i = 0; i < n_peers; i++)
        dl += snprintf(dial + dl, sizeof dial - dl, "%s%s", dl ? "," : "", peers[i]);
    { sqlite3 *cdb = idx_db_open(db);
      if (cdb) {
          char dn[8][80]; int nd = idx_db_peers_agent(cdb, IDX_DNET_MARK, dn, 8);
          for (int i = 0; i < nd && dl < (int)sizeof dial - 84; i++)
              dl += snprintf(dial + dl, sizeof dial - dl, "%s%s", dl ? "," : "", dn[i]);
          idx_db_close(cdb);
      } }

    /* resolver handles (separate connections; WAL-safe) */
    g_core_ch = dns_chain_open(db);
    g_core.st = sp_state_open(store);
    if (!g_core_ch || !g_core.st) { fprintf(stderr, "cannot open resolver handles\n"); return 1; }
    g_core.oracle = dns_chain_oracle(g_core_ch);
    g_core.verbose = g_verbose;

    /* optional control socket (live PUT/DEL/CLEAR via dns-cli) */
    if (ctl_path) {
        unlink(ctl_path);
        g_ctl_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un un; memset(&un, 0, sizeof un);
        un.sun_family = AF_UNIX;
        snprintf(un.sun_path, sizeof un.sun_path, "%s", ctl_path);
        if (bind(g_ctl_fd, (struct sockaddr *)&un, sizeof un) < 0 || listen(g_ctl_fd, 4) < 0) {
            perror("ctl socket"); close(g_ctl_fd); g_ctl_fd = -1;
        } else {
            fcntl(g_ctl_fd, F_SETFL, O_NONBLOCK);
            g_ctl_path = ctl_path;
            fprintf(stderr, "dnsd: control socket %s\n", ctl_path);
        }
    }

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    signal(SIGPIPE, SIG_IGN);

    /* net thread: the chain-wire mesh + NODE_NETWORK_LIMITED serve */
    struct netargs na = { coin, db, store, dial, chain_port };
    pthread_t nt; pthread_create(&nt, NULL, net_main, &na);

    /* sync thread: keep the ownership db + serve window fresh (unless external) */
    pthread_t st_th; int have_sync = 0;
    struct syncargs sa = { coin, db, sync_peer };
    if (do_sync) { pthread_create(&st_th, NULL, sync_main, &sa); have_sync = 1; }

    /* DNS server (main thread): UDP + TCP on the same addr/port via the extracted
     * core. TCP (RFC 7766) is needed for answers past the UDP budget and because
     * compliant resolvers probe it. */
    if (dnsd_core_bind(&g_core, dns_addr, dns_port) != 0) g_stop = 1;

    if (!g_stop)
        fprintf(stderr, "dnsd: DNS on %s:%d (udp+%s)  chain listen=%u peers=%d sync=%s  suffix=.%s  magic=%02x%02x\n",
                dns_addr, dns_port, g_core.tfd >= 0 ? "tcp" : "udp-only",
                chain_port, n_peers, do_sync ? sync_peer : "off", g_core.suffix,
                onchain_magic[0], onchain_magic[1]);

    while (!g_stop)
        dnsd_core_poll(&g_core, 500);

    pthread_join(nt, NULL);
    if (have_sync) pthread_join(st_th, NULL);
    dnsd_core_close(&g_core);
    if (g_ctl_fd >= 0) close(g_ctl_fd);
    if (g_ctl_path) unlink(g_ctl_path);
    sp_state_close(g_core.st); dns_chain_close(g_core_ch);
    fprintf(stderr, "dnsd: stopped\n");
    return 0;
}
