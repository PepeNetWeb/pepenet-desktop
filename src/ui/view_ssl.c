// view_ssl.c — the per-name SSL screen (9d/9e): a certificate LIST, not one
// cert. The default apex certificate covers <name> + *.<name> under one key;
// per-subdomain certificates carry their OWN key (a sub hosted elsewhere
// leaks only its own key if that host is compromised). Every entry shows its
// pin state against the zone's `_443._tcp*` TLSA: pinned ✓ · not-pinned-yet !
// (publish button) · mismatch ✕ (republish). Certs are sscert files on disk
// (~/.pepenet/origin-<host>.<tld>.{crt,key}); pins publish through
// dnsnet_publish — creating a cert auto-publishes its pin.
#include "ui.h"
#include "../dnsnet.h"
#include "../webproxy.h"
#include "../dirscan.h"
#include "../platform.h"
#include "dns_wire.h"

#include "../../vendor/sokol/sokol_app.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

// ── cert enumeration: origin-<host>.<tld>.crt files under this apex ──────────
typedef struct {
    char    host[64];       // TLD-less: "gm" (apex) or "shop.gm"
    uint8_t spki[32];
    int64_t created;        // crt mtime
    int     is_apex;
    int     wildcard;       // cert's SAN carries *.<host> (covers subdomains)
} CertEnt;

static CertEnt g_ce[16];
static int     g_nce;
static char    g_ce_apex[64];
static int64_t g_ce_at;
static int     g_ce_dirty;

static int ce_cmp(const void *a, const void *b) {
    const CertEnt *x = a, *y = b;
    if (x->is_apex != y->is_apex) return y->is_apex - x->is_apex;   // apex first
    return strcmp(x->host, y->host);
}

static void ce_scan(const char *apex) {
    if (!g_ce_dirty && strcmp(g_ce_apex, apex) == 0 && M.now - g_ce_at < 5) return;
    snprintf(g_ce_apex, sizeof g_ce_apex, "%s", apex);
    g_ce_at = M.now;
    g_ce_dirty = 0;
    g_nce = 0;

    char dirp[512];
    platform_data_dir(dirp, sizeof dirp);
    DIR *d = opendir(dirp);
    if (!d) return;
    const char *pre = "origin-", *suf = APP_DOT_TLD ".crt";
    size_t prel = strlen(pre), sufl = strlen(suf), apl = strlen(apex);
    struct dirent *e;
    while ((e = readdir(d)) && g_nce < 16) {
        size_t nl = strlen(e->d_name);
        if (nl <= prel + sufl || strncmp(e->d_name, pre, prel) != 0) continue;
        if (strcmp(e->d_name + nl - sufl, suf) != 0) continue;
        char host[64];
        size_t hl = nl - prel - sufl;
        if (hl == 0 || hl >= sizeof host) continue;
        memcpy(host, e->d_name + prel, hl);
        host[hl] = 0;
        int is_apex = strcmp(host, apex) == 0;
        int is_sub = hl > apl + 1 && host[hl - apl - 1] == '.' &&
                     strcmp(host + hl - apl, apex) == 0;
        if (!is_apex && !is_sub) continue;
        CertEnt *c = &g_ce[g_nce];
        if (!webproxy_origin_probe(host, c->spki)) continue;
        snprintf(c->host, sizeof c->host, "%s", host);
        c->is_apex = is_apex;
        c->wildcard = webproxy_origin_wildcard(host);
        struct stat st;
        char full[600];
        snprintf(full, sizeof full, "%s/%s", dirp, e->d_name);
        c->created = stat(full, &st) == 0 ? (int64_t)st.st_mtime : 0;
        g_nce++;
    }
    closedir(d);
    qsort(g_ce, (size_t)g_nce, sizeof g_ce[0], ce_cmp);
}

void ui_ssl_dirty(void) { g_ce_dirty = 1; }

// TLSA label for a host under this apex: "gm" → "_443._tcp";
// "shop.gm" → "_443._tcp.shop"
static void tlsa_label(const char *host, const char *apex, char *out, size_t cap) {
    size_t hl = strlen(host), al = strlen(apex);
    if (hl == al) { snprintf(out, cap, "_443._tcp"); return; }
    snprintf(out, cap, "_443._tcp.%.*s", (int)(hl - al - 1), host);
}

// pin state vs the folded zone: 2 = pinned (match) · 1 = pinned other key
// (mismatch) · 0 = no TLSA yet
static int pin_state(const zone *z, int nrec, const char *label,
                     const uint8_t spki[32]) {
    for (int i = 0; i < nrec; i++) {
        const zone_rec *r = &z->recs[i];
        if (r->type != DNS_TLSA || strcmp(r->label, label) != 0) continue;
        if (r->rdlen == 35 && r->rdata[0] == 3 && r->rdata[1] == 1 &&
            r->rdata[2] == 1)
            return memcmp(r->rdata + 3, spki, 32) == 0 ? 2 : 1;
        return 1;
    }
    return 0;
}

// publish `3 1 1 <spki>` at the host's TLSA label (one place: dnsnet_publish_tlsa)
static void publish_pin(const char *apex, const char *host, const uint8_t spki[32]) {
    (void)apex;
    if (dnsnet_publish_tlsa(host, spki)) dirscan_kick();
}

static void reveal_in_finder(const char *path) {
    platform_reveal_file(path);
}

// host chip pill; returns width consumed
static float chip(struct nk_context *ctx, float x, float y, const char *text) {
    float w = dk_w(F_SM11, text) + 22;
    struct nk_rect r = nk_rect(x, y, w, 22);
    dk_card(ctx, r, 11, C_INPUT, C_BORDER);
    dk_text_c(ctx, F_SM11, r, C_TEXT, text);
    return w;
}

// ── one certificate entry card (9d); returns its height ──────────────────────
static float cert_card(struct nk_context *ctx, float x, float xr, float y,
                       const char *apex, const CertEnt *c, const zone *z,
                       int nrec, int measure) {
    char b[128];
    char label[80];
    tlsa_label(c->host, apex, label, sizeof label);
    int ps = pin_state(z, nrec, label, c->spki);

    float head_h = 46, strip_h = 38, pin_h = 26, meta_h = 32;
    float h = head_h + 12 + strip_h + 10 + pin_h + meta_h;
    if (measure) return h;

    struct nk_rect card = nk_rect(x, y, xr - x, h);
    dk_card(ctx, card, 10, C_PANEL, C_BORDER);

    // header: host chips + role label · Delete · Export bundle
    float cxp = x + 14;
    snprintf(b, sizeof b, "%s" APP_DOT_TLD, c->host);
    cxp += chip(ctx, cxp, y + 12, b) + 6;
    if (c->wildcard) {
        snprintf(b, sizeof b, "*.%s" APP_DOT_TLD, c->host);
        cxp += chip(ctx, cxp, y + 12, b) + 10;
    } else cxp += 4;
    dk_text_sp(ctx, F_SMB9, cxp, y + 18, C_GHOST,
               c->is_apex ? (c->wildcard ? TR(S_SSL_ROLE_DEFAULT)
                                         : TR(S_SSL_ROLE_APEX))
                          : TR(S_SSL_ROLE_SUB), 1);
    {
        const char *lbl = TR(S_SSL_EXPORT);
        float ew = dk_w(F_PH12, lbl) + 24;
        struct nk_rect eb = nk_rect(xr - 14 - ew, y + 11, ew, 25);
        if (dk_btn_col(ctx, eb, F_PH12, lbl, BTN_LINE_FILL, C_TEXT))
            reveal_in_finder(webproxy_origin_crt(c->host));
        const char *dl = TR(S_SSL_DELETE);
        float dw = dk_w(F_PH12, dl) + 24;
        struct nk_rect db = nk_rect(eb.x - 8 - dw, y + 11, dw, 25);
        if (!M.demo && dk_btn_col(ctx, db, F_PH12, dl, BTN_LINE, C_RED)) {
            snprintf(UI.ssl_del_host, sizeof UI.ssl_del_host, "%s", c->host);
            UI.ssl_del_keep_pin = 0;
            UI.dialog = DLG_SSL_DEL;
        }
    }
    dk_hline(ctx, x + 1, xr - 1, y + head_h, C_BORDER);
    float yy = y + head_h + 12;

    // pin strip: ✓ pinned (olive) · ! not pinned (accent + publish) · ✕ mismatch
    struct nk_rect strip = nk_rect(x + 14, yy, xr - x - 28, strip_h);
    if (ps == 2) {
        dk_card(ctx, strip, 9, C_TINT_OK, C_TINT_OK_BR);
        dk_text(ctx, F_SM13, strip.x + 12, yy + 10, C_GREEN, "\xE2\x9C\x93");
        dk_text(ctx, F_PH14, strip.x + 32, yy + 9, HEXC(0xCDD7AD),
                TR(S_SSL_PINNED_OK));
    } else {
        int mism = ps == 1;
        dk_card(ctx, strip, 9, mism ? C_TINT_RED : C_TINT_ACC,
                mism ? C_TINT_RED_BR : C_TINT_ACC_BR);
        dk_text(ctx, F_SM13, strip.x + 12, yy + 10,
                mism ? C_RED : C_ACCENT, mism ? "\xE2\x9C\x95" : "!");
        snprintf(b, sizeof b, mism
                 ? TR(S_SSL_PIN_MISMATCH_FMT)
                 : TR(S_SSL_PIN_MISSING_FMT),
                 c->host);
        dk_clip_push(ctx, nk_rect(strip.x, yy, strip.w - 116, strip_h));
        dk_text(ctx, F_PH14, strip.x + 32, yy + 9,
                mism ? HEXC(0xE8B7A4) : HEXC(0xB2DDA1), b);
        dk_clip_pop(ctx);
        struct nk_rect pb = nk_rect(strip.x + strip.w - 104, yy + 7, 94, 24);
        if (!M.demo &&
            dk_btn(ctx, pb, F_PH12, mism ? TR(S_SSL_REPUBLISH) : TR(S_SSL_PUBLISH_PIN), BTN_ACCENT))
            publish_pin(apex, c->host, c->spki);
    }
    yy += strip_h + 10;

    // KEY PIN row
    dk_text_sp(ctx, F_SM9, x + 14, yy + 3, C_GHOST, TR(S_SSL_KEYPIN_LABEL), 1);
    char hex[70];
    size_t o = 0;
    for (int i = 0; i < 32; i++)
        o += (size_t)snprintf(hex + o, sizeof hex - o, "%02x", c->spki[i]);
    float px0 = x + 168, px1 = xr - 78;
    dk_clip_push(ctx, nk_rect(px0, yy, px1 - px0, pin_h));
    dk_text(ctx, F_SM11, px0, yy + 2, ps == 2 ? C_GREEN : C_DIM, hex);
    dk_clip_pop(ctx);
    {
        struct nk_rect cb = nk_rect(xr - 70, yy - 2, 56, 22);
        if (dk_btn_col(ctx, cb, F_PH12, TR(S_SSL_COPY), BTN_GHOST, C_DIM))
            sapp_set_clipboard_string(hex);
    }
    yy += pin_h;

    // meta
    dk_hline(ctx, x + 14, xr - 14, yy, C_HAIR);
    yy += 9;
    float mx = x + 14;
    dk_text(ctx, F_SM10, mx, yy, C_GHOST, TR(S_SSL_KIND_SELF));
    mx += dk_w(F_SM10, TR(S_SSL_KIND_SELF)) + 18;
    dk_text(ctx, F_SM10, mx, yy, C_GHOST, TR(S_SSL_KEY_ALGO));
    mx += dk_w(F_SM10, TR(S_SSL_KEY_ALGO)) + 18;
    if (c->created) {
        char db[32];
        fmt_date_long(db, sizeof db, c->created);
        snprintf(b, sizeof b, TR(S_SSL_CREATED_FMT), db);
        dk_text(ctx, F_SM10, mx, yy, C_GHOST, b);
        mx += dk_w(F_SM10, b) + 18;
    }
    dk_text(ctx, F_SM10, mx, yy, C_GHOST, TR(S_SSL_VALIDITY));
    return h;
}

void view_ssl(struct nk_context *ctx, struct nk_rect area) {
    int ni = ui_dns_pick_name();
    if (ni < 0) {
        struct nk_rect r = nk_rect(area.x + 40, area.y + 60, area.w - 80, 62);
        dk_rect_dashed(ctx, r, 12, C_BORDER);
        dk_text_c(ctx, F_PH16, r, C_DIM, TR(S_SSL_EMPTY_NONAME));
        return;
    }
    const char *apex = M.names[ni].name;
    float top = ui_name_header(ctx, area, apex, TR(S_SSL_WHICH), TR(S_SSL_LINK_DNS), V_DNS);

    if (!M.demo) ce_scan(apex);
    int nce = M.demo ? 0 : g_nce;
    int have_apex = 0;
    for (int i = 0; i < nce; i++) have_apex |= g_ce[i].is_apex;

    zone z;
    int nrec = M.demo ? 0 : dnsnet_zone(apex, &z);
    if (nrec < 0) nrec = 0;

    struct nk_rect view = nk_rect(area.x, top, area.w, area.y + area.h - top);
    dk_scroll_begin(ctx, &UI.sc_ssl, view);
    float x = view.x + 16, xr = view.x + view.w - 16;
    float y = view.y + 14 - UI.sc_ssl.scroll;
    char b[160];

    if (!have_apex) {
        // ── 9e: empty state — Create panel is the page focus ─────────────────
        float ph = 258;
        float lw = (xr - x - 16) * 0.52f;
        struct nk_rect lp = nk_rect(x, y, lw, ph);
        dk_fill(ctx, lp, 10, HEXC(0x1E2019));
        dk_rect_dashed(ctx, lp, 10, C_BORDER);
        dk_text_c(ctx, F_PH18, nk_rect(lp.x, lp.y + ph / 2 - 42, lp.w, 24), C_DIM,
                  TR(S_SSL_EMPTY_TITLE));
        snprintf(b, sizeof b, TR(S_SSL_EMPTY_BODY_FMT), apex);
        dk_wrap(ctx, F_PH12, lp.x + 30, lp.y + ph / 2 - 8, lp.w - 60, C_GHOST, b, 1.35f);

        struct nk_rect rp = nk_rect(x + lw + 16, y, xr - x - lw - 16, ph);
        dk_card(ctx, rp, 10, C_PANEL, C_ACCENT);
        dk_text(ctx, F_PH16, rp.x + 16, rp.y + 10, C_TEXT, TR(S_SSL_CREATE_TITLE));
        dk_hline(ctx, rp.x + 1, rp.x + rp.w - 1, rp.y + 40, C_BORDER);
        float ry = rp.y + 50;
        dk_wrap(ctx, F_PH12, rp.x + 16, ry, rp.w - 32, C_DIM,
                TR(S_SSL_CREATE_BODY), 1.3f);
        ry += 42;
        dk_text_sp(ctx, F_SM9, rp.x + 16, ry, C_GHOST, TR(S_SSL_COVERS), 1);
        ry += 16;
        float cxp = rp.x + 16;
        snprintf(b, sizeof b, "%s" APP_DOT_TLD, apex);
        cxp += chip(ctx, cxp, ry, b) + 8;
        if (!UI.ssl_no_wild) {
            snprintf(b, sizeof b, "*.%s" APP_DOT_TLD, apex);
            chip(ctx, cxp, ry, b);
        }
        ry += 28;
        // wildcard choice — checked = the SAN carries *.<apex> too
        {
            struct nk_rect cbx = nk_rect(rp.x + 16, ry, 15, 15);
            if (UI.ssl_no_wild) dk_line_rect(ctx, cbx, 4, C_GHOST);
            else {
                dk_fill(ctx, cbx, 4, C_ACCENT);
                dk_text_c(ctx, F_SM9, cbx, C_ONFILL, "\xE2\x9C\x93");
            }
            snprintf(b, sizeof b, TR(S_SSL_WILD_FMT), apex);
            dk_text(ctx, F_PH12, cbx.x + 22, ry, C_DIM, b);
            struct nk_rect hit = nk_rect(cbx.x, ry - 2, 22 + dk_w(F_PH12, b), 19);
            if (dk_hot(ctx, hit)) sapp_set_mouse_cursor(SAPP_MOUSECURSOR_POINTING_HAND);
            if (dk_click(ctx, hit)) UI.ssl_no_wild = !UI.ssl_no_wild;
        }
        ry += 26;
        struct nk_rect note = nk_rect(rp.x + 16, ry, rp.w - 32, 40);
        dk_card(ctx, note, 8, C_TINT_OK, C_TINT_OK_BR);
        dk_text(ctx, F_SM11, note.x + 10, ry + 5, C_GREEN, "\xE2\x86\x91");
        dk_clip_push(ctx, note);
        dk_wrap(ctx, F_PH12, note.x + 26, ry + 4, note.w - 38, C_DIM,
                TR(S_SSL_CREATE_NOTE), 1.25f);
        dk_clip_pop(ctx);
        struct nk_rect cb = nk_rect(rp.x + rp.w - 16 - 96, rp.y + ph - 42, 96, 30);
        if (M.demo) {
            ui_btn_disabled(ctx, cb, F_PH14, TR(S_SSL_CREATE));
        } else if (UI.web_busy > 0) {
            ui_btn_disabled(ctx, cb, F_PH14, UI.web_note);
            UI.web_busy--;
        } else if (dk_btn(ctx, cb, F_PH14, TR(S_SSL_CREATE), BTN_GREEN)) {
            uint8_t spki[32]; int created = 0;
            if (webproxy_origin_ensure(apex, !UI.ssl_no_wild, spki, &created)) {
                publish_pin(apex, apex, spki);        // create auto-publishes
                ui_ssl_dirty();
            } else {
                snprintf(UI.web_note, sizeof UI.web_note, "%s", TR(S_SSL_GEN_FAILED));
                UI.web_busy = 150;
            }
        }
        y += ph + 12;
    } else {
        // ── 9d: the certificate list ──────────────────────────────────────────
        dk_text(ctx, F_PH16, x + 2, y, C_TEXT, TR(S_SSL_CERTS_TITLE));
        snprintf(b, sizeof b, TR(S_SSL_NCERTS_FMT), nce);
        dk_text(ctx, F_SM10, x + 2 + dk_w(F_PH16, TR(S_SSL_CERTS_TITLE)) + 10, y + 5,
                C_GHOST, b);
        y += 30;
        for (int i = 0; i < nce; i++)
            y += cert_card(ctx, x, xr, y, apex, &g_ce[i], &z, nrec, 0) + 12;

        // add-subdomain (dashed action card)
        {
            struct nk_rect ar = nk_rect(x, y, xr - x, 58);
            dk_fill(ctx, ar, 10, HEXC(0x1E2019));
            dk_rect_dashed(ctx, ar, 10, HEXC(0x464A38));
            dk_text(ctx, F_PH14, x + 16, y + 8, C_TEXT, TR(S_SSL_ADD_SUB));
            dk_text(ctx, F_SM10, x + 16, y + 32, C_GHOST,
                    TR(S_SSL_ADD_SUB_BODY));
            struct nk_rect ab = nk_rect(xr - 16 - 72, y + 14, 72, 30);
            if (!M.demo &&
                dk_btn_col(ctx, ab, F_PH14, TR(S_SSL_ADD_BTN), BTN_LINE_FILL, C_TEXT)) {
                UI.dialog = DLG_SSL_SUB;
                UI.ssl_sub_len = 0;
                UI.ssl_sub[0] = 0;
            }
            y += 58 + 12;
        }

        // pin-status legend
        float lx = x + 2;
        dk_text_sp(ctx, F_SM9, lx, y + 3, C_GHOST, TR(S_SSL_LEGEND), 1);
        lx += dk_w_sp(F_SM9, TR(S_SSL_LEGEND), 1) + 18;
        dk_text(ctx, F_SM11, lx, y + 2, C_GREEN, "\xE2\x9C\x93");
        dk_text(ctx, F_PH12, lx + 14, y + 1, C_FADE3, TR(S_SSL_LEG_PINNED));
        lx += 14 + dk_w(F_PH12, TR(S_SSL_LEG_PINNED)) + 18;
        dk_text(ctx, F_SM11, lx, y + 2, C_ACCENT, "!");
        dk_text(ctx, F_PH12, lx + 12, y + 1, C_FADE3, TR(S_SSL_LEG_UNPINNED));
        lx += 12 + dk_w(F_PH12, TR(S_SSL_LEG_UNPINNED)) + 18;
        dk_text(ctx, F_SM11, lx, y + 2, C_RED, "\xE2\x9C\x95");
        dk_text(ctx, F_PH12, lx + 14, y + 1, C_FADE3, TR(S_SSL_LEG_MISMATCH));
        y += 24;
    }

    // ── orphaned pins: TLSA rows whose certificate is gone from this machine ─
    // (deleted with "keep pin", or minted elsewhere). Without this strip they'd
    // be unreachable — the DNS page locks _443._tcp* rows as SSL-owned, and
    // pin controls above only exist on a cert's card.
    if (!M.demo) for (int i = 0; i < nrec; i++) {
        const zone_rec *r = &z.recs[i];
        if (r->type != DNS_TLSA || strncmp(r->label, "_443._tcp", 9) != 0) continue;
        char host[80];
        if (r->label[9] == '.')
            snprintf(host, sizeof host, "%s.%s", r->label + 10, apex);
        else if (r->label[9] == 0)
            snprintf(host, sizeof host, "%s", apex);
        else continue;
        int have = 0;
        for (int k = 0; k < nce && !have; k++)
            if (strcmp(g_ce[k].host, host) == 0) have = 1;
        if (have) continue;
        struct nk_rect strip = nk_rect(x, y, xr - x, 40);
        dk_card(ctx, strip, 9, C_TINT_RED, C_TINT_RED_BR);
        dk_text(ctx, F_SM13, strip.x + 12, y + 11, C_RED, "!");
        snprintf(b, sizeof b, TR(S_SSL_ORPHAN_FMT), host);
        dk_clip_push(ctx, nk_rect(strip.x, y, strip.w - 116, 40));
        dk_text(ctx, F_PH14, strip.x + 28, y + 10, HEXC(0xE8B7A4), b);
        dk_clip_pop(ctx);
        float uw = dk_w(F_PH12, TR(S_SSL_UNPIN)) + 22;
        struct nk_rect ub = nk_rect(strip.x + strip.w - 10 - uw, y + 8, uw, 24);
        if (dk_btn_col(ctx, ub, F_PH12, TR(S_SSL_UNPIN), BTN_LINE, C_RED)) {
            dnsnet_unpublish_tlsa(host);   // queued; the strip clears when the
            dirscan_kick();                // tombstone folds (a few seconds)
        }
        y += 48;
    }

    if (M.demo) {
        dk_text(ctx, F_SM10, x + 2, y + 4, C_GHOST,
                TR(S_SSL_DEMO_NOTE));
        y += 24;
    }
    y += 8;
    dk_scroll_end(ctx, &UI.sc_ssl, view, (y + UI.sc_ssl.scroll) - view.y, 0);
}
