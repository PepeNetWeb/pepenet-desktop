// gd_node.c — one headless process, one coin. greatdane-node starts the pep
// or doge instance (DNS + DANE proxy + sync) under --data/<coin>/. Two
// engines in one process are refused: the indexer still has process globals.
// No UI libraries. Never touches ~/.pepenet; --data is required.
#include "appinst.h"
#include "engine.h"
#include "dnsnet.h"
#include "webproxy.h"
#include "wallet.h"
#include "platform.h"
#include "indexer.h"        /* idx_serve_listen_status: local status only */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <poll.h>
#include <pthread.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

DeskWallet WLT;   // zeroed: this process has no wallet (dnsnet's publish path)

/* webproxy.c calls these on the default-instance path. greatdane-node always
 * sets an instance data dir before start, so they must not create ~/.pepenet. */
const char *platform_data_dir(char *out, size_t cap) {
    if (out && cap) out[0] = 0;
    return out ? out : "";
}
const char *platform_data_path(const char *name, char *out, size_t cap) {
    if (!out || !cap) return "";
    snprintf(out, cap, "%s", name ? name : "");
    return out;
}

static volatile int g_run = 1;
static void on_sig(int s) { (void)s; g_run = 0; }

/* Shutdown bound: the browser expects its child gone within ~1 s of stdin
 * EOF or SIGTERM. Peer waits are stop-aware now, but a blocking
 * getaddrinfo() cannot be interrupted, so a watchdog ends the process if
 * the orderly teardown overruns. SQLite commits are atomic, so _exit
 * mid-pass loses at most the uncommitted batch, which the next run refetches. */
#define GD_STOP_GRACE_MS 700
static void *stop_watchdog(void *arg) {
    (void)arg;
    usleep(GD_STOP_GRACE_MS * 1000);
    fprintf(stderr, "greatdane-node: teardown exceeded %d ms, exiting\n", GD_STOP_GRACE_MS);
    _exit(0);
    return NULL;
}

static void refuse_dual(void) {
    fprintf(stderr,
        "greatdane-node: two engines in one process are blocked by indexer globals:\n"
        "  idx_sync_stop\n"
        "  g_self_nonce\n"
        "  g_self_ip\n"
        "  s_parity\n"
        "  g_serve_mesh\n"
        "  g_conns\n"
        "  g_crawl\n"
        "  idx_self_seed\n"
        "  idx_sync_agent\n"
        "  idx_sync_peer_height\n"
        "  idx_sync_peer_agent\n"
        "  idx_sync_peer_services\n"
        "  idx_serve_stage_seq\n"
        "  mempool.c g_mu g_tbucket g_pbucket g_count g_bytes g_seen g_seen_head g_seen_n\n"
        "  net_policy.c g_ban g_nban\n"
        "  digest.c g_s\n"
        "Pass --only pep or --only doge.\n");
}

/* --ephemeral-ports: ask the kernel for a free loopback port (TCP and UDP
 * both free, since dnsnet binds both). Small bind race; M1 only. */
static int free_port(void) {
    for (int tries = 0; tries < 50; tries++) {
        int t = socket(AF_INET, SOCK_STREAM, 0);
        if (t < 0) return -1;
        struct sockaddr_in a; memset(&a, 0, sizeof a);
        a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t l = sizeof a;
        if (bind(t, (struct sockaddr *)&a, sizeof a) || getsockname(t, (struct sockaddr *)&a, &l)) { close(t); return -1; }
        int u = socket(AF_INET, SOCK_DGRAM, 0);
        int ok = u >= 0 && bind(u, (struct sockaddr *)&a, sizeof a) == 0;
        if (u >= 0) close(u);
        close(t);
        if (ok) return ntohs(a.sin_port);
    }
    return -1;
}

static int mkdir_p(const char *path) {
    char tmp[512];
    snprintf(tmp, sizeof tmp, "%s", path);
    size_t n = strlen(tmp);
    if (n == 0 || n + 1 >= sizeof tmp) return -1;
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = 0;
        if (mkdir(tmp, 0700) != 0 && errno != EEXIST) return -1;
        *p = '/';
    }
    if (mkdir(tmp, 0700) != 0 && errno != EEXIST) return -1;
    return 0;
}

/* --seeds: local override of the first-dial candidates (the chain's built-in
 * DNS seeds still follow as fallbacks inside the indexer). Charset-checked;
 * no wire effect beyond which peer is dialled first. */
static int seeds_valid(const char *s) {
    size_t n = strlen(s);
    if (n == 0 || n > 255) return 0;
    for (const char *p = s; *p; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || strchr(".-:,[]_", *p))) return 0;
    return 1;
}

static double mono_s(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + t.tv_nsec / 1e9;
}

static void json_safe(char *dst, size_t cap, const char *src) {
    size_t o = 0;
    for (const char *p = src; *p && o + 3 < cap; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\') { dst[o++] = '\\'; dst[o++] = (char)c; }
        else if (c < 0x20) dst[o++] = ' ';
        else dst[o++] = (char)c;
    }
    dst[o] = 0;
}

/* One status line (no trailing newline). Field set is append-only: older
 * readers ignore the new keys. */
static void build_status(char *out, size_t cap, const char *coin, const char *dir) {
    EngineStatus es; memset(&es, 0, sizeof es); engine_status(&es);
    WebStatus ws; memset(&ws, 0, sizeof ws); webproxy_status(&ws);
    int ptotal = 0, pmesh = 0;
    EnginePeer pr[1]; engine_peers(pr, 0, &ptotal, &pmesh);
    int lst = 0, lport = 0, lerr = 0;
    idx_serve_listen_status(&lst, &lport, &lerr);
    const char *lname = lst == IDX_LISTEN_OK ? "ok"
                      : lst == IDX_LISTEN_FAILED ? "bind_failed"
                      : lst == IDX_LISTEN_OFF ? "off" : "pending";
    char lmsg[96] = "";
    if (lst == IDX_LISTEN_FAILED && lerr) json_safe(lmsg, sizeof lmsg, strerror(lerr));
    static IdxServeConn cs[64];
    int nc = idx_serve_conns(cs, 64), pin = 0, pout = 0;
    for (int i = 0; i < nc; i++)
        if (cs[i].connected && cs[i].up) { if (cs[i].outbound) pout++; else pin++; }
    int64_t ph = es.peer_height > idx_serve_best_height() ? es.peer_height : idx_serve_best_height();
    double pct = 0;
    if (ph > 0) pct = es.height >= ph ? 100.0 : 100.0 * (double)es.height / (double)ph;
    const char *state = !es.running ? "stopped"
                      : (es.passes == 0 && !es.pass_active && es.height == 0) ? "starting"
                      : ph <= 0 ? "connecting"
                      : es.height + 2 < ph ? "syncing" : "ready";
    char dd[600]; json_safe(dd, sizeof dd, dir);
    snprintf(out, cap,
        "{\"event\":\"status\",\"coin\":\"%s\",\"height\":%lld,"
        "\"peer_height\":%lld,\"activation\":%lld,\"engine\":%d,"
        "\"pass_active\":%d,\"passes\":%lld,\"peers_known\":%d,"
        "\"peers_pepenet\":%d,\"conns\":%lld,\"dane_ok\":%lld,"
        "\"dane_fail\":%lld,\"listen\":\"%s\",\"listen_port\":%d,"
        "\"listen_errno\":%d,\"listen_error\":\"%s\","
        "\"state\":\"%s\",\"sync_pct\":%.1f,\"peers_in\":%d,\"peers_out\":%d,"
        "\"data_dir\":\"%s\"}",
        coin, (long long)es.height, (long long)es.peer_height,
        (long long)es.activation, es.running, es.pass_active,
        (long long)es.passes, ptotal, pmesh, (long long)ws.conns,
        (long long)ws.dane_ok, (long long)ws.dane_fail,
        lname, lport, lerr, lmsg, state, pct, pin, pout, dd);
}

int main(int argc, char **argv) {
    const char *data = NULL, *only = NULL, *seeds = NULL;
    const char *snap_dir = NULL, *snap_pin = NULL;   /* idx-04 */
    int ephemeral = 0, stdio_ctl = 0, dane_api = 0, listen_port = -1;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--data") && i + 1 < argc) data = argv[++i];
        else if (!strcmp(argv[i], "--only") && i + 1 < argc) only = argv[++i];
        else if (!strcmp(argv[i], "--ephemeral-ports")) ephemeral = 1;
        else if (!strcmp(argv[i], "--dane-api")) dane_api = 1;
        else if (!strcmp(argv[i], "--stdio")) stdio_ctl = 1;
        else if (!strcmp(argv[i], "--seeds") && i + 1 < argc) seeds = argv[++i];
        else if (!strcmp(argv[i], "--no-listen")) listen_port = 0;
        else if (!strcmp(argv[i], "--snapshot") && i + 1 < argc) snap_dir = argv[++i];
        else if (!strcmp(argv[i], "--snapshot-sha256") && i + 1 < argc) snap_pin = argv[++i];
        else if (!strcmp(argv[i], "--listen-port") && i + 1 < argc) {
            char *e; long v = strtol(argv[++i], &e, 10);
            if (*e || v < 1 || v > 65535) {
                fprintf(stderr, "greatdane-node: --listen-port must be 1..65535 (use --no-listen to disable)\n");
                return 2;
            }
            listen_port = (int)v;
        }
        else {
            fprintf(stderr, "usage: greatdane-node --data <dir> --only pep|doge [--ephemeral-ports] [--dane-api] [--stdio] [--seeds host[:port],...]\n"
                            "       [--listen-port N | --no-listen] [--snapshot <dir> [--snapshot-sha256 <hex>]]\n");
            return 2;
        }
    }
    if (!data || !data[0]) {
        fprintf(stderr, "greatdane-node: --data is required (this process never uses ~/.pepenet)\n");
        return 2;
    }
    if (!only) { refuse_dual(); return 2; }
    if (strcmp(only, "pep") != 0 && strcmp(only, "doge") != 0) {
        fprintf(stderr, "greatdane-node: --only must be pep or doge\n");
        return 2;
    }

    if (seeds && !seeds_valid(seeds)) {
        fprintf(stderr, "greatdane-node: --seeds must be a comma list of host[:port] (max 255 chars)\n");
        return 2;
    }
    const AppInstance *inst = app_instance_by_coin(only);
    if (!inst) { fprintf(stderr, "greatdane-node: unknown coin\n"); return 2; }
    static AppInstance eph;
    if (ephemeral) {
        eph = *inst;
        /* TCP listeners: port 0, bound by the kernel and read back after
         * start (no race). The DNS resolver binds UDP+TCP on one number, so
         * it still picks first; a lost race makes the node exit nonzero and
         * the browser supervisor respawns it with fresh ports. */
        eph.dns_port = free_port(); eph.proxy_port = 0;
        eph.pac_port = 0; eph.pf_port = 0;
        if (eph.dns_port < 0) {
            fprintf(stderr, "greatdane-node: no free loopback ports\n"); return 1;
        }
        inst = &eph;
    }

    char dir[512], db[600];
    snprintf(dir, sizeof dir, "%s/%s", data, inst->coin);
    if (mkdir_p(dir) != 0) { perror("greatdane-node mkdir"); return 1; }
    snprintf(db, sizeof db, "%s/%s.db", dir, inst->coin);

    /* idx-04: optional pinned snapshot bootstrap, BEFORE anything opens the db.
     * Applied only to a fresh data dir, and only if state.db's whole-file
     * SHA-256 equals the pin (--snapshot-sha256 overrides the compiled per-chain
     * default). Any refusal — no pin, bad pin, mismatch, truncation, bad
     * MANIFEST — is logged and the node simply full-syncs from the checkpoint.
     * A refusal never aborts startup and never leaves a partial db. */
    if (snap_dir) {
        char why[400];
        if (idx_snapshot_import(inst->coin, snap_dir, db, snap_pin, why, sizeof why))
            fprintf(stderr, "greatdane-node: snapshot: %s\n", why);
        else
            fprintf(stderr, "greatdane-node: snapshot REFUSED: %s — falling back to full sync\n", why);
    } else if (snap_pin) {
        fprintf(stderr, "greatdane-node: --snapshot-sha256 ignored (no --snapshot <dir>)\n");
    }

    app_set_data_base(data);
    /* Combined mode splices to the static table's ports; an ephemeral
     * (browser-supervised, one process per chain) node serves only its TLD. */
    if (!ephemeral) webproxy_set_combined(1);
    if (dane_api) webproxy_set_passthrough(1);   /* M3: browser verifies DANE */
    dnsnet_use_chain_db(db);

    /* inbound chain-port listener: CLI beats PEPENET_DNS_LISTEN; default is
     * the chain's own port (pep 33874, doge 22556). Not affected by
     * --ephemeral-ports, which only moves the loopback DNS/proxy/PAC ports. */
    if (listen_port >= 0) {
        char lp[8]; snprintf(lp, sizeof lp, "%d", listen_port);
        setenv("PEPENET_DNS_LISTEN", lp, 1);
    }
    Dnsnet *dn = dnsnet_start_inst(inst);
    if (!dn) { fprintf(stderr, "greatdane-node: dnsnet_start_inst failed\n"); return 1; }
    Webproxy *wp = webproxy_start_inst(inst, dn);
    if (!wp) {
        fprintf(stderr, "greatdane-node: webproxy_start_inst failed\n");
        dnsnet_stop();
        return 1;
    }
    Engine *en = engine_start_inst(inst, db, seeds ? seeds : inst->seeds);
    if (!en) {
        fprintf(stderr, "greatdane-node: engine_start_inst failed\n");
        webproxy_stop();
        dnsnet_stop();
        return 1;
    }

    fprintf(stderr, "greatdane-node: coin=%s tld=%s dns=%d proxy=%d pac=%d pf=%d db=%s\n",
            inst->coin, inst->tld, inst->dns_port, inst->proxy_port,
            inst->pac_port, inst->pf_port, db);

    if (ephemeral) {
        webproxy_ports(&eph.proxy_port, &eph.pac_port, &eph.pf_port);
        if (!eph.proxy_port || !eph.pac_port) {
            fprintf(stderr, "greatdane-node: proxy listeners did not bind\n");
            webproxy_stop(); dnsnet_stop(); engine_stop();
            return 1;
        }
    }
    if (stdio_ctl) {
        /* One JSON line on stdout for the browser launcher; then the node
         * lives exactly as long as its parent keeps stdin open. No "ca"
         * field: the browser verifies DANE itself and never trusted a node
         * root (and --dane-api mints none). */
        printf("{\"event\":\"ready\",\"coin\":\"%s\",\"tld\":\"%s\",\"dns\":%d,"
               "\"proxy\":%d,\"pac\":%d,\"pf\":%d,\"dane_api\":%d}\n",
               inst->coin, inst->tld, inst->dns_port, inst->proxy_port,
               inst->pac_port, inst->pf_port, dane_api);
        fflush(stdout);
    }

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    /* Status: one JSON line whenever a display field changes (at most once
     * per second), a heartbeat every 3 s, and on {"cmd":"status"} from stdin.
     * Local stdio only; nothing goes on the P2P wire. */
    char last_line[2048] = "";
    double last_emit = 0, last_beat = 0;
    char inbuf[512]; size_t inlen = 0;
    int force = 1;
    while (g_run) {
        if (stdio_ctl) {
            char line[2048];
            build_status(line, sizeof line, inst->coin, dir);
            double now = mono_s();
            int changed = strcmp(line, last_line) != 0;
            if (force || (changed && now - last_emit >= 1.0) || now - last_beat >= 3.0) {
                fputs(line, stdout); fputc('\n', stdout); fflush(stdout);
                snprintf(last_line, sizeof last_line, "%s", line);
                last_beat = now; if (changed || force) last_emit = now;
                force = 0;
            }
            struct pollfd pf = { 0, POLLIN, 0 };
            if (poll(&pf, 1, 250) > 0) {
                ssize_t n = read(0, inbuf + inlen, sizeof inbuf - 1 - inlen);
                if (n <= 0) break;              /* parent gone: exit */
                inlen += (size_t)n; inbuf[inlen] = 0;
                char *nl;
                while ((nl = strchr(inbuf, '\n')) != NULL) {
                    *nl = 0;
                    if (strstr(inbuf, "\"cmd\":\"status\"")) force = 1;
                    size_t rest = inlen - (size_t)(nl + 1 - inbuf);
                    memmove(inbuf, nl + 1, rest + 1); inlen = rest;
                }
                if (inlen >= sizeof inbuf - 1) inlen = 0;   /* overlong line: drop */
            }
        } else sleep(1);
    }

    { pthread_t wd; if (pthread_create(&wd, NULL, stop_watchdog, NULL) == 0) pthread_detach(wd); }
    idx_sync_stop = 1;  /* start unwinding the sync pass while the listeners close */
    webproxy_stop();
    dnsnet_stop();
    engine_stop();
    return 0;
}
