// pepenet-desktop ("PepeNet") — the decentralized-web client. sokol+nuklear
// shell over the embedded indexers/c engine; the full owner-drawn UI lives in
// src/ui/ (visual system inherited from pepenet-desktop).
//
// Architecture rules (inherited from pepenet-desktop/src/README.md):
//   - the app NEVER re-implements the fold — consensus is the compiled-in
//     protocol-sm engine driven by indexers/c sync, same bytes as indexerd;
//   - the UI thread only reads projections (engine.h); the sync thread writes;
//   - the dns/web plane (dnsnet.c mesh + resolver, webproxy.c DANE proxy)
//     embeds the same way in later slices: each engine owns its thread and
//     store, the UI reads status snapshots.
//
// Args: pepenet-desktop [--demo] [dbpath] [peer-ip] [coin]
// (defaults: ~/.pepenet/pep.db, the pep seed peer, "pep")
#include "../vendor/sokol/sokol_app.h"
#include "../vendor/sokol/sokol_gfx.h"
#include "../vendor/sokol/sokol_glue.h"
#include "../vendor/sokol/sokol_log.h"

#include "ui/nk_config.h"
#include "../vendor/sokol/util/sokol_nuklear.h"

#include "appconf.h"
#include "engine.h"
#include "indexer.h"        // idx_sync_agent (our P2P subver)
#include "model.h"
#include "dnsnet.h"
#include "zonekey.h"
#include "webproxy.h"
#include "dirscan.h"
#include "favicon.h"
#include "sysinstall.h"
#include "platform.h"
#include "dns_wire.h"       // DNS_TLSA (the CERT_DUMP proof hook)
#include "dns_state.h"      // DNS_SCOPE + op builders (ZONE_DUMP proof)
#include "pepenet/state.h"  // SpCert / sp_cert_parse / sp_cert_verify / sp_state_op_*
#include "pepenet/crypto.h" // sp_hash160
#include "wallet.h"
#include "ops.h"
#include "ui/theme.h"
#include "ui/ui.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

void tray_setup(void);
void tray_update(void);
void tray_hide_window(void);
void tray_background_start(void);   // --background: start hidden, tray only
void tray_test_close(void);
void tray_test_quit(void);
void tray_test_dump(void);
int  tray_quit_requested(void);

#define DEFAULT_PEER APP_SEED_PEER
#define DEFAULT_COIN APP_COIN

// Global zoom on top of the display's dpi scale: the whole design canvas
// (layout + fonts) renders 1.25× larger. Fonts stay retina-crisp — the atlas
// bakes at the combined scale. Window sizes below grow by the same factor so
// the visible logical area stays the design's 560-wide canvas.
#define UI_SCALE 1.25f
static float px_scale(void) { return sapp_dpi_scale() * UI_SCALE; }
// the logical→device factor, for views that must snap to whole device pixels
// (the QR grid — see view_receive). One source of truth for the scale.
float app_px_scale(void) { return px_scale(); }

static struct {
    char dbpath[512], ip[64], coin[16];
    int demo;
    int background;             // --background (login agent): start hidden
    int frames;
    int engines_up;             // wallet/engine/dns/web/dirscan booted
    int lockfd;                 // held write-lock on <coin>.db.lock
} S;

// ── single-writer guard: two desktops sharing <coin>.db = two sync writers.
// An flock on <coin>.db.lock (advisory, shared convention with the sibling
// desktops) gates every engine boot; blocked = DLG_LOCKED with Retry.
static int db_lock_try(void) {
    if (S.lockfd > 0) return 1;
    char p[560];
    snprintf(p, sizeof p, "%s.lock", S.dbpath);
    int fd = open(p, O_CREAT | O_RDWR, 0644);
    if (fd < 0) return 1;                       // can't even create: don't block
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        close(fd);
        return 0;
    }
    S.lockfd = fd;                              // held for the process lifetime
    return 1;
}

// ── external-origin auto-refresh ──────────────────────────────────────────────
// everything that writes the shared data dir, deferred until the lock is ours
static void engines_boot(void) {
    if (S.engines_up) return;
    idx_sync_agent = APP_CHAIN_AGENT;   // our P2P subver, before ANY thread dials
                                        // (the mesh serve thread starts first)
    // WEB PLANE FIRST. wallet_boot below can block MINUTES on the macOS
    // Keychain prompt (every re-signed build is a "new app" to the Keychain,
    // so every rebuild re-asks). With the old wallet-first order that stall
    // kept the resolver + DANE proxy dark while /etc/resolver + pf still
    // steered the browser at their ports — ".pepe https is broken after every
    // rebuild" until the prompt was answered. Nothing here needs the wallet:
    // the publish path pulls the wallet key lazily, at publish time.
    dnsnet_boot(S.coin, S.dbpath);
    // the mesh now rides the chain wire: dnsnet's net thread runs idx_serve,
    // which dials the crawl-discovered marked peers itself (chain port) —
    // no separate 9953 bridge, no dnsnet_add_peer needed here.
    dnsnet_start();
    webproxy_start(dnsnet_store_path(), dnsnet_chain_path());
    dirscan_start(dnsnet_store_path(), dnsnet_chain_path());
    // wallet + everything keyed by it (the Keychain gate lives here)
    if (wallet_boot(S.coin, S.dbpath)) {
        engine_watch(S.dbpath, WLT.h160);
        ops_init(S.coin, S.dbpath, S.ip, WLT.h160);
    }
    zonekey_boot(S.coin, S.dbpath);     // hot zone key the wallet delegates to
    engine_start(S.coin, S.dbpath, S.ip);
    S.engines_up = 1;
}

// DLG_LOCKED's Retry lands here (ui reaches through this seam)
int app_db_locked(void) { return !S.demo && !S.engines_up; }
int app_db_retry(void) {
    if (!db_lock_try()) return 0;
    engines_boot();
    return 1;
}

static void default_dbpath(char *out, size_t cap) {
    char name[32];
    snprintf(name, sizeof name, "%s.db", S.coin);
    platform_data_path(name, out, cap);
}

// PEPENET_OPEN=<view|dialog>[,tok…]: dev hook to land on any state straight
// from launch (headless screenshots / view walks). Comma-separated tokens
// apply left to right. Live mode honors only the plain view keys;
// fixture-touching states are demo-only.
static void apply_open_tok(const char *o) {
    if (!strcmp(o, "discover")) UI.view = V_DISCOVER;
    else if (!strcmp(o, "names")) UI.view = V_NAMES;
    else if (!strcmp(o, "market")) UI.view = V_MARKET;
    else if (!strcmp(o, "receive")) UI.view = V_RECEIVE;
    else if (!strcmp(o, "dns")) UI.view = V_DNS;
    else if (!strcmp(o, "ssl")) UI.view = V_SSL;
    else if (!strcmp(o, "consent")) UI.dialog = DLG_CONSENT;
    else if (!strcmp(o, "peers")) UI.view = V_PEERS;
    else if (!strcmp(o, "settings")) UI.view = V_SETTINGS;
    else if (!strcmp(o, "send")) {          // prefill = gate screenshots
        UI.view = V_SEND;
        snprintf(UI.send_to, sizeof UI.send_to, "shibs-list");
        UI.send_to_len = 10;
        snprintf(UI.send_amt, sizeof UI.send_amt, "5.00");
        UI.send_amt_len = 4;
    }
    else if (!strcmp(o, "claim")) {         // fixture-free: UI fields only
        UI.dialog = DLG_CLAIM;
        UI.claim_days = 365;
        snprintf(UI.claim_name, sizeof UI.claim_name, "much-wow");
        UI.claim_name_len = 8;
    }
    if (!M.demo) return;
    // fixture-touching states below (demo only)
    if (!strcmp(o, "names-sel")) { UI.view = V_NAMES; UI.sel_mask = 0x7; UI.name_expanded = 1; }
    else if (!strcmp(o, "names-listed")) { UI.view = V_NAMES; UI.name_expanded = 2; }
    else if (!strcmp(o, "balance")) { UI.popup = POP_BALANCE; UI.pop_anchor = nk_rect(424, 44, 120, 28); }
    else if (!strcmp(o, "renew")) { UI.dialog = DLG_RENEW; UI.name_target = 1; UI.renew_days = 353; }
    else if (!strcmp(o, "batch")) { UI.dialog = DLG_BATCH_RENEW; UI.sel_mask = 0x7; }
    else if (!strcmp(o, "batch-transfer")) { UI.dialog = DLG_BATCH_TRANSFER; UI.sel_mask = 0x7; UI.send_to_len = 0; }
    else if (!strcmp(o, "sell")) { UI.dialog = DLG_SELL; UI.name_target = 0; UI.sell_days = 30; snprintf(UI.sell_price, sizeof UI.sell_price, "40.0"); UI.sell_price_len = 4; }
    else if (!strcmp(o, "release")) { UI.dialog = DLG_RELEASE; UI.name_target = 0; }
    else if (!strcmp(o, "bid")) { UI.dialog = DLG_BID; UI.listing_target = 0; }
    else if (!strcmp(o, "reclaim")) {              // self-buy dialog on our OWN listing
        UI.dialog = DLG_BID;
        UI.listing_target = 0;
        for (int i = 0; i < M.nlist; i++) if (M.listings[i].is_mine) { UI.listing_target = i; break; }
    }
    else if (!strcmp(o, "settle")) {
        // reserve window is 5h (SM_RESERVE_WINDOW) — the countdown must fit it
        M.listings[0].reserved_by_me = 1;
        M.listings[0].reserve_end = M.now + 3 * 3600 + 41 * 60 + 8;
        UI.dialog = DLG_SETTLE;
        UI.listing_target = 0;
    }
    else if (!strcmp(o, "blocked")) { UI.dialog = DLG_BLOCKED; UI.listing_target = 3; }
    else if (!strcmp(o, "payoffer")) { UI.dialog = DLG_PAYOFFER; UI.offer_target = 0; }
    else if (!strcmp(o, "transfer")) {          // invalid-address state
        UI.dialog = DLG_TRANSFER;
        UI.name_target = 0;
        snprintf(UI.send_to, sizeof UI.send_to, "not-an-address");
        UI.send_to_len = (int)strlen(UI.send_to);
    }
    else if (!strcmp(o, "claim-bad")) {         // invalid-name state
        UI.dialog = DLG_CLAIM;
        UI.claim_days = 365;
        snprintf(UI.claim_name, sizeof UI.claim_name, "Much Wow!");
        UI.claim_name_len = (int)strlen(UI.claim_name);
    }
    else if (!strcmp(o, "dnsrec")) {            // 9f: add-record modal, error state
        UI.view = V_DNS;
        UI.dialog = DLG_DNS_REC;
        UI.dnsm_edit = 0; UI.dnsm_type_sel = 0; UI.dnsm_more = 0;
        snprintf(UI.dnsm_host, sizeof UI.dnsm_host, "shop"); UI.dnsm_host_len = 4;
        snprintf(UI.dnsm_ttl, sizeof UI.dnsm_ttl, "3600"); UI.dnsm_ttl_len = 4;
        snprintf(UI.dnsm_val, sizeof UI.dnsm_val, "104.21.9.999"); UI.dnsm_val_len = 12;
    }
    else if (!strcmp(o, "dnsrec-edit")) {       // 9g: edit modal, pre-filled
        UI.view = V_DNS;
        UI.dialog = DLG_DNS_REC;
        UI.dnsm_edit = 1; UI.dnsm_type_sel = 0; UI.dnsm_more = 1;
        snprintf(UI.dnsm_orig_label, sizeof UI.dnsm_orig_label, "api");
        UI.dnsm_orig_type = 1;
        snprintf(UI.dnsm_host, sizeof UI.dnsm_host, "api"); UI.dnsm_host_len = 3;
        snprintf(UI.dnsm_ttl, sizeof UI.dnsm_ttl, "300"); UI.dnsm_ttl_len = 3;
        snprintf(UI.dnsm_val, sizeof UI.dnsm_val, "104.21.9.51"); UI.dnsm_val_len = 11;
    }
    else if (!strcmp(o, "sslsub")) {            // 9d: subdomain-cert dialog
        UI.view = V_SSL;
        UI.dialog = DLG_SSL_SUB;
        snprintf(UI.ssl_sub, sizeof UI.ssl_sub, "shop"); UI.ssl_sub_len = 4;
    }
    else if (!strcmp(o, "poor")) M.balance = 4000000;      // 0.04 — gates most spends
    else if (!strcmp(o, "rich")) M.balance = 500000000000; // 5,000 — gates nothing
}

static void apply_open_hook(void) {
    const char *env = getenv("PEPENET_OPEN");
    if (!env) return;
    char buf[256];
    snprintf(buf, sizeof buf, "%s", env);
    for (char *sv = 0, *tok = strtok_r(buf, ",", &sv); tok; tok = strtok_r(0, ",", &sv))
        apply_open_tok(tok);
}

static void init(void) {
    // A --background spawn racing a live instance: launchd fires a RunAtLoad
    // agent the moment it is (re)registered — i.e. on every Settings
    // toggle-ON — and again at each login even when the user already opened
    // the app by hand. The primary instance holds the db lock; this copy
    // would only plant a second tray icon and then linger invisibly behind a
    // hidden DLG_LOCKED. Nothing has started yet — vanish instead. (Normal
    // foreground double-launches keep the visible lock dialog.)
    if (!S.demo && S.background && !db_lock_try())
        exit(0);
    sg_setup(&(sg_desc){ .environment = sglue_environment(), .logger.func = slog_func });
    snk_setup(&(snk_desc_t){
        .dpi_scale = px_scale(),
        .no_default_font = true,
        .logger.func = slog_func,
    });
    platform_style_window(UI_SCALE);
    if (!S.demo) tray_setup();
    if (!S.demo && S.background) tray_background_start();   // login agent: no window
    if (getenv("PEPENET_SELFTEST"))     // wallet's own vectors, in-process
        fprintf(stderr, "wallet selftest: %s\n",
                swl_selftest() == 0 ? "PASS" : "FAIL");
    if (!S.demo) {
        // dev wallet + chain sync + dns plane + DANE proxy + directory — all
        // of it behind the single-writer lock (engines_boot); a second desktop
        // on the same data dir gets DLG_LOCKED instead of a WAL fight
        if (db_lock_try())
            engines_boot();
    } else {
        // no keys in demo, but address validation still needs the coin's
        // base58 version byte
        snprintf(WLT.coin, sizeof WLT.coin, "%s", S.coin);
    }
    model_init(S.demo, (int64_t)time(NULL));
    apply_open_hook();
    // 9h: first-run consent — shows once (marker file records the answer);
    // never over a headless hook, which must not block on a modal
    if (!S.demo && UI.dialog == DLG_NONE && !getenv("PEPENET_OPEN") &&
        !getenv("PEPENET_DIR_DUMP") && !getenv("PEPENET_CERT_DUMP") &&
        !getenv("PEPENET_ZONE_DUMP") && !getenv("PEPENET_SECRET_TEST") &&
        !sysinstall_consent_seen())
        UI.dialog = DLG_CONSENT;
    if (!S.demo && !S.engines_up)
        UI.dialog = DLG_LOCKED;         // the lock dialog outranks consent
    // a wallet minted this launch exists nowhere but this Mac's keychain —
    // queue the 12-word backup nag (ui_frame opens it once consent/lock have
    // cleared the stage). Same headless-hook guards as consent: a modal must
    // never block a scripted run.
    if (!S.demo && WLT.created && !getenv("PEPENET_OPEN") &&
        !getenv("PEPENET_DIR_DUMP") && !getenv("PEPENET_CERT_DUMP") &&
        !getenv("PEPENET_ZONE_DUMP") && !getenv("PEPENET_SECRET_TEST"))
        UI.backup_pending = 1;
    // launch-at-login defaults ON — applied once, then the Settings toggle is
    // the only writer; an enabled agent is refreshed so its executable path
    // and args track this binary. Skipped over headless hooks.
    if (!S.demo && !getenv("PEPENET_OPEN") && !getenv("PEPENET_DIR_DUMP") &&
        !getenv("PEPENET_CERT_DUMP") && !getenv("PEPENET_ZONE_DUMP") &&
        !getenv("PEPENET_SECRET_TEST"))
        sysinstall_loginitem_default();
}

static int themed;
static void cleanup(void);

// Exit path for the headless hooks (SMOKE/DIR_DUMP/CERT_DUMP): stop the
// engines cleanly (DB flush matters) but skip the GPU/nuklear teardown — the
// process is exiting anyway, and snk_shutdown aborts in nk_font_atlas_clear
// under no_default_font (the old exit-134 quirk, which also poisoned macOS's
// crash history and made every relaunch block on the "reopen windows?" alert).
static void hook_exit(int code) {
    if (!S.demo) {
        favicon_stop();
        dirscan_stop();
        webproxy_stop();
        dnsnet_stop();
        engine_stop();
    }
    exit(code);
}

static void frame(void) {
    // --background belt-and-suspenders: sokol orders the window front after
    // init, so re-hide on the first frame in case init's orderOut lost the race
    if (S.background && S.frames == 0 && !S.demo) tray_background_start();
    if (S.frames++ % 60 == 0) model_tick((int64_t)time(NULL));   // ~1 Hz
    else M.now = (int64_t)time(NULL);
    // smoke hook: PEPENET_EXIT_AFTER=<frames> — render that many frames, print
    // a proof line, exit. (The view walk: PEPENET_OPEN=<view> + this.)
    {
        const char *ea = getenv("PEPENET_EXIT_AFTER");
        if (ea && S.frames >= atoi(ea)) {
            InstallState is;
            sysinstall_probe(&is);
            fprintf(stderr, "SMOKE OK frames=%d view=%d dialog=%d ca=%d resolver=%d pf=%d\n",
                    S.frames, (int)UI.view, (int)UI.dialog,
                    is.ca_trusted, is.resolver_file, is.pf_anchor);
            hook_exit(0);
        }
    }
    // headless proof hook: PEPENET_DIR_DUMP prints the directory snapshot once
    // ~8 s in (after gossip + a rebuild), then exits — no window needed.
    if (!S.demo && getenv("PEPENET_DIR_DUMP") && S.frames == 60 * 8) {
        DirRow dr[DIR_MAX]; int64_t ba = 0; int lm = 0;
        int dn = dirscan_snapshot(dr, DIR_MAX, &ba, &lm);
        fprintf(stderr, "DIRDUMP built_at=%lld ms=%d rows=%d\n", (long long)ba, lm, dn);
        for (int i = 0; i < dn; i++)
            fprintf(stderr, "DIRROW %-16s A=%d TLSA=%d reg=%d nrec=%d ip=%s\n",
                    dr[i].name, dr[i].has_a, dr[i].has_tlsa, dr[i].registered,
                    dr[i].nrec, dr[i].a_ip);
        hook_exit(0);
    }
    // headless proof hook: PEPENET_CERT_DUMP=<apex> drives the DNS-tab origin
    // cert flow without a click — ensure the cert + publish its TLSA (~8 s in,
    // wallet must own <apex>), then re-fold and report the match (~16 s), exit.
    if (!S.demo && getenv("PEPENET_CERT_DUMP")) {
        const char *apex = getenv("PEPENET_CERT_DUMP");
        if (S.frames == 60 * 8) {
            uint8_t spki[32]; int created = 0;
            if (!webproxy_origin_ensure(apex, 1, spki, &created)) {
                fprintf(stderr, "CERTDUMP ensure FAILED\n");
                hook_exit(1);
            }
            fprintf(stderr, "CERTDUMP ensured created=%d crt=%s\n",
                    created, webproxy_origin_crt(apex));
            char rdata[80];
            size_t o = (size_t)snprintf(rdata, sizeof rdata, "3 1 1 ");
            for (int i = 0; i < 32; i++)
                o += (size_t)snprintf(rdata + o, sizeof rdata - o, "%02x", spki[i]);
            zone_rec rec;
            if (zone_build_rec("_443._tcp", "TLSA", 3600, rdata, &rec) != 0) {
                fprintf(stderr, "CERTDUMP build_rec FAILED\n");
                hook_exit(1);
            }
            dnsnet_publish(apex, &rec);
            fprintf(stderr, "CERTDUMP published %s\n", rdata);
        }
        if (S.frames == 60 * 16) {
            uint8_t spki[32];
            int present = webproxy_origin_probe(apex, spki);
            zone z; int n = dnsnet_zone(apex, &z);
            int match = 0;
            for (int i = 0; present && n > 0 && i < z.n; i++)
                if (z.recs[i].type == DNS_TLSA && !strcmp(z.recs[i].label, "_443._tcp") &&
                    z.recs[i].rdlen == 35 && !memcmp(z.recs[i].rdata + 3, spki, 32))
                    match = 1;
            fprintf(stderr, "CERTDUMP present=%d zonerecs=%d match=%d\n",
                    present, n, match);
            hook_exit(match ? 0 : 1);
        }
    }
    // headless proof: PEPENET_ZONE_DUMP=<name> proves the cert-delegate path —
    // the hot zone key is distinct from the wallet, the wallet mints a DNS_SCOPE
    // delegation cert for it, and a record signed by the HOT key (never the
    // wallet) verifies with the wallet as the on-chain owner.
    if (!S.demo && getenv("PEPENET_ZONE_DUMP") && S.frames == 60) {
        const char *name = getenv("PEPENET_ZONE_DUMP");
        uint32_t tip = (uint32_t)(M.height ? M.height : 1107268);
        int distinct = memcmp(WLT.pub, ZK.pub, 33) != 0;
        fprintf(stderr, "ZONEDUMP wallet_ok=%d zonekey_ok=%d distinct_hot_key=%d\n",
                WLT.ok, ZK.ok, distinct);

        uint8_t cert[256];
        int cl = zonekey_cert(name, tip, cert, sizeof cert);
        SpCert vc; int parsed = cl > 0 && sp_cert_parse(SP_CERT_P2PKH, cert, cl, &vc);
        int deleg  = parsed && memcmp(vc.posting_key, ZK.pub, 33) == 0;
        int scoped = parsed && (vc.scope & DNS_SCOPE);
        uint8_t oh[20]; sp_hash160(WLT.pub, 33, oh);        // the wallet IS the owner
        int cverify = parsed && sp_cert_verify(&vc, (const uint8_t *)name,
                                               (int)strlen(name), ZK.pub, tip, oh);
        fprintf(stderr, "ZONEDUMP cert_len=%d deleg_to_hot=%d dns_scope=%d not_after=%u verify=%d\n",
                cl, deleg, scoped, parsed ? vc.not_after : 0, cverify);

        // a record op signed by the HOT key under the cert, verified the way
        // admission verifies it: parse → sig over op_id → cert binds hot key
        // to the wallet-owner at this anchor
        zone_rec rec; int haverec = zone_build_rec("www", "A", 3600, "5.6.7.8", &rec) == 0;
        uint8_t key[SP_STATE_KEY_MAX], pay[600], ah[32] = {0}, entry[SP_STATE_OP_MAX];
        int kl = haverec ? dns_key_pack(rec.label, rec.type, key, sizeof key) : -1;
        int pl = haverec ? dns_payload_pack(rec.ttl, rec.rdata, rec.rdlen, pay, sizeof pay) : -1;
        int n = (kl > 0 && pl > 0)
              ? sp_state_op_build(SP_OP_PUT, name, key, kl, pay, pl, tip, ah,
                                  ZK.seckey, ZK.pub, SP_CERT_P2PKH, cert, cl,
                                  entry, sizeof entry)
              : -1;
        SpStateOp op;
        int rv = n > 0 && sp_state_op_parse(entry, n, &op)
              && sp_ecdsa_verify(op.op_id, op.sig, op.signer, 33)
              && op.has_cert == SP_CERT_P2PKH
              && sp_cert_verify(&op.cert, (const uint8_t *)name, (int)strlen(name),
                                op.signer, op.anchor, oh);
        fprintf(stderr, "ZONEDUMP hot_signed_record=%d verifies_under_owner=%d\n",
                n > 0, rv);
        fprintf(stderr, "ZONEDUMP zonekey_file=%s\n", ZK.path);
        hook_exit((distinct && deleg && scoped && cverify && rv) ? 0 : 1);
    }
    // headless proof: PEPENET_SECRET_TEST — round-trip the OS keystore primitive
    // on a throwaway account, then report the wallet-key migration state (key in
    // the keystore, plaintext file gone). Run with PEPENET_KEYCHAIN_SERVICE set
    // to an isolated service so it never touches the real wallet item.
    if (!S.demo && getenv("PEPENET_SECRET_TEST") && S.frames == 60) {
        uint8_t s[32], rt[32];
        for (int i = 0; i < 32; i++) s[i] = (uint8_t)(i * 7 + 1);
        int setok = platform_secret_set("selftest-tmp", s, 32);
        int got   = platform_secret_get("selftest-tmp", rt, sizeof rt);
        int match = got == 32 && memcmp(rt, s, 32) == 0;
        int delok = platform_secret_del("selftest-tmp");
        int gone  = platform_secret_get("selftest-tmp", rt, sizeof rt) == 0;
        fprintf(stderr, "SECRETTEST roundtrip set=%d get=%d match=%d del=%d gone=%d\n",
                setok, got, match, delok, gone);

        char acct[32]; snprintf(acct, sizeof acct, "wallet-%s", S.coin);
        uint8_t wk[32];
        // the HD wallet stores 16-byte BIP39 entropy (a legacy item is 32)
        int wn = platform_secret_get(acct, wk, sizeof wk);
        int in_keystore = wn == 16 || wn == 32;
        int file_present = access(WLT.path, R_OK) == 0;
        fprintf(stderr, "SECRETTEST wallet_in_keystore=%d legacy_file_present=%d wallet_ok=%d addr=%s\n",
                in_keystore, file_present, WLT.ok, WLT.address);
        hook_exit((match && gone && in_keystore && !file_present && WLT.ok) ? 0 : 1);
    }
    // headless proof hooks for the tray lifecycle. CLOSE_TEST drives
    // performClose: (the exact red-button path) at ~2 s, then proves the
    // process survived the veto with the window hidden — AppKit's deferred
    // last-window-closed check runs ~1 s after the close, so surviving to
    // frame 300 means the tray.m delegate patch held. If the veto is broken
    // the app dies before the line. QUIT_TEST then (or alone) drives the
    // tray's Quit at ~7 s: expect "cleanup called" + plain exit 0, no abort.
    if (!S.demo && getenv("PEPENET_CLOSE_TEST")) {
        // PEPENET_CLOSE_TEST=<frame> moves the dump/exit point (default 300 ≈
        // 5 s) — a live proof that needs the engines' first slow beats (the
        // carrier dials on a 5 s tick) dumps later, e.g. 900 ≈ 15 s.
        int dumpf = atoi(getenv("PEPENET_CLOSE_TEST"));
        if (dumpf <= 120) dumpf = 300;
        if (S.frames == 120) tray_test_close();
        if (S.frames == dumpf) {
            fprintf(stderr, "CLOSETEST alive visible=%d\n", platform_window_visible());
            tray_test_dump();
            if (!getenv("PEPENET_QUIT_TEST")) hook_exit(0);
        }
        if (getenv("PEPENET_QUIT_TEST") && S.frames == dumpf + 120)
            tray_test_quit();
    } else if (!S.demo && getenv("PEPENET_QUIT_TEST") && S.frames == 420)
        tray_test_quit();
    // tray-resident (meld §4): while the window is hidden, keep the engines
    // ticking (the model refresh above already ran on the 1 Hz beat) but skip
    // rendering entirely — no drawable, ~0 CPU. The menu-bar item stays live.
    if (!S.demo && S.frames % 60 == 1) tray_update();
    if (!S.demo && !platform_window_visible()) return;

    model_refresh_pending();            // per-frame: track the ops queue live so a
                                        // button's disabled state never lags or
                                        // latches a 1 Hz-sampled transient

    struct nk_context *ctx = snk_new_frame();
    if (!themed) { theme_init(ctx, px_scale()); themed = 1; }
    float scale = px_scale();
    ui_frame(ctx, sapp_widthf() / scale, sapp_heightf() / scale);

    sg_begin_pass(&(sg_pass){ .action = { .colors[0] = {
        .load_action = SG_LOADACTION_CLEAR,
        .clear_value = { ((TH_BG >> 16) & 0xFF) / 255.0f,
                         ((TH_BG >> 8) & 0xFF) / 255.0f,
                         (TH_BG & 0xFF) / 255.0f, 1.0f } } },
        .swapchain = sglue_swapchain() });
    snk_render(sapp_width(), sapp_height());
    sg_end_pass();
    sg_commit();
}

static void input(const sapp_event *ev) {
    // window-close (and ⌘Q via the menu-bar Quit) → sokol posts QUIT_REQUESTED.
    // Unless the tray's real Quit was chosen, veto it and hide the window warm.
    if (ev->type == SAPP_EVENTTYPE_QUIT_REQUESTED && !S.demo) {
        int really = tray_quit_requested();
        if (getenv("PEPENET_CLOSE_TEST"))
            fprintf(stderr, "CLOSETEST quit_requested really=%d\n", really);
        if (!really) sapp_cancel_quit();
        return;
    }
    // minimize also goes to the tray, not the Dock — one hidden-warm state
    if (ev->type == SAPP_EVENTTYPE_ICONIFIED && !S.demo) {
        tray_hide_window();
        return;
    }
    snk_handle_event(ev);
}

static void cleanup(void) {
    if (getenv("PEPENET_CLOSE_TEST") || getenv("PEPENET_QUIT_TEST"))
        fprintf(stderr, "CLOSETEST cleanup called\n");
    if (!S.demo) {
        favicon_stop();                 // fetches through the proxy — stop first
        dirscan_stop();
        webproxy_stop();                // consumers stop before their stores' writers
        dnsnet_stop();                  // reads the chain db — stop before the engine
        engine_stop();
    }
    // no snk_shutdown/sg_shutdown: the process is exiting (only path here is
    // applicationWillTerminate), and snk_shutdown aborts in nk_font_atlas_clear
    // under no_default_font — every real Quit was dying by SIGABRT (exit 134)
    // AFTER the engines stopped, which kept re-poisoning macOS crash history.
}

sapp_desc sokol_main(int argc, char *argv[]) {
    const char *pos[3] = { 0, 0, 0 };
    int npos = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--demo")) S.demo = 1;
        else if (!strcmp(argv[i], "--background")) S.background = 1;
        else if (npos < 3) pos[npos++] = argv[i];
    }
    snprintf(S.coin, sizeof S.coin, "%s", pos[2] ? pos[2] : DEFAULT_COIN);
    if (pos[0]) snprintf(S.dbpath, sizeof S.dbpath, "%s", pos[0]);
    else default_dbpath(S.dbpath, sizeof S.dbpath);
    snprintf(S.ip, sizeof S.ip, "%s", pos[1] ? pos[1] : DEFAULT_PEER);
    return (sapp_desc){
        .init_cb = init, .frame_cb = frame, .event_cb = input, .cleanup_cb = cleanup,
        .width = 700, .height = 880,       // design 560×704 logical × UI_SCALE
        .high_dpi = true,
        .enable_clipboard = true,
        .window_title = APP_NAME,
        .logger.func = slog_func,
    };
}
