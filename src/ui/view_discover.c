// view_discover.c — Discover, the home view (9a): the enumerable website
// directory as a card grid. The chain IS the registry, so the set is listable
// — this is the join of names-with-zones × the registry, rebuilt off-thread by
// dirscan. Card art is the site's real favicon when the DANE proxy can fetch
// one (favicon.c — pin-verified path), else a generated identicon; the
// description comes from the owner's `_site` TXT record, clamped to two
// lines. Clicking a servable card launches the real system browser.
#include "ui.h"
#include "../dirscan.h"
#include "../webproxy.h"
#include "../sysinstall.h"
#include "../favicon.h"

#include "../../vendor/sokol/sokol_app.h"
#include "../../vendor/sokol/sokol_gfx.h"
#include "../../vendor/sokol/util/sokol_nuklear.h"

#include <string.h>
#include <stdio.h>

#include "../platform.h"

// ── favicon textures: decoded RGBA (favicon.c) → one sg image per site ───────
typedef struct { char name[40]; struct nk_image img; } FavTex;
static FavTex g_ft[128];
static int    g_nft;
static sg_sampler g_ft_smp;                    // shared linear sampler

// the site's favicon as a drawable nk_image, or NULL (not fetched / failed —
// caller falls back to the identicon). Uploads happen here, on the UI thread,
// at most one texture per site per run.
static const struct nk_image *fav_tex(const char *name) {
    for (int i = 0; i < g_nft; i++)
        if (strcmp(g_ft[i].name, name) == 0) return &g_ft[i].img;
    const uint8_t *rgba; int w, h;
    if (favicon_query(name, &rgba, &w, &h) != FAV_READY) return NULL;
    if (g_nft >= 128) return NULL;
    if (g_ft_smp.id == 0)
        g_ft_smp = sg_make_sampler(&(sg_sampler_desc){
            .min_filter = SG_FILTER_LINEAR, .mag_filter = SG_FILTER_LINEAR,
            .label = "favicon-smp",
        });
    sg_image img = sg_make_image(&(sg_image_desc){
        .width = w, .height = h,
        .pixel_format = SG_PIXELFORMAT_RGBA8,
        .data.mip_levels[0] = { .ptr = rgba, .size = (size_t)w * (size_t)h * 4 },
        .label = "favicon",
    });
    sg_view view = sg_make_view(&(sg_view_desc){ .texture.image = img });
    snk_image_t si = snk_make_image(&(snk_image_desc_t){
        .texture_view = view, .sampler = g_ft_smp });
    FavTex *f = &g_ft[g_nft++];
    snprintf(f->name, sizeof f->name, "%s", name);
    f->img = nk_image_handle(snk_nkhandle(si));
    return &f->img;
}

// launch https://<name>.<tld> in the user's browser
static void visit(const char *name) {
    char url[96];
    snprintf(url, sizeof url, "https://%s" APP_DOT_TLD "/", name);
    platform_open_url(url);
}

// install-state probe, cached ~5 s (shared shape with view_settings)
static InstallState g_inst;
static int64_t g_inst_at;
static const InstallState *inst_state(void) {
    if (M.now - g_inst_at >= 5) { sysinstall_probe(&g_inst); g_inst_at = M.now; }
    return &g_inst;
}

static int q_match(const DirRow *r, const char *q) {
    return strstr(r->name, q) != NULL || strstr(r->site, q) != NULL;
}

// one card (9a): icon (favicon / identicon) LEFT · name row + description
// right · servable dot / INFO chip at the top-right corner
#define CARD_ICON 52
#define CARD_H    84
static void card(struct nk_context *ctx, struct nk_rect r, const DirRow *d,
                 int web_ready) {
    int servable = d->has_a && d->has_tlsa && d->registered;
    int lapsed = !d->registered;
    int hot = !lapsed && dk_hot(ctx, r);

    struct nk_color cbg = lapsed ? HEXC(0x1E2019) : hot ? HEXC(0x24261D) : C_PANEL;
    struct nk_color cbr = lapsed ? C_INPUT : C_BORDER;
    dk_card(ctx, r, 10, cbg, cbr);

    // icon well at the left: the real favicon when the proxy has fetched one
    // (servable sites only — the fetch path IS the DANE path), else identicon
    struct nk_rect well = nk_rect(r.x + 12, r.y + (CARD_H - CARD_ICON) / 2,
                                  CARD_ICON, CARD_ICON);
    dk_fill(ctx, well, 8, C_BG);
    const struct nk_image *fv = (servable && !lapsed) ? fav_tex(d->name) : NULL;
    if (fv) {
        struct nk_rect ir = nk_rect(well.x + 4, well.y + 4,
                                    well.w - 8, well.h - 8);
        nk_draw_image(dk_cv(ctx), ir, fv, nk_rgba(255, 255, 255, 255));
    } else {
        float icon = 3 * 13 + 2 * 3;
        dk_identicon(ctx, well.x + (well.w - icon) / 2,
                     well.y + (well.h - icon) / 2, 13, 3, d->name, lapsed);
    }
    if (servable)
        dk_dot(ctx, r.x + r.w - 14, r.y + 14, 7, C_GREEN);
    else if (!lapsed && !d->has_a)
        dk_text_r(ctx, F_SMB9, r.x + r.w - 10, r.y + 9, C_GHOST, TR(S_DISC_INFO));

    // name row + description to the icon's right
    float tx = well.x + well.w + 12, ty = r.y + 14;
    float tw = r.x + r.w - 14 - tx;
    dk_text(ctx, F_SM14, tx, ty, lapsed ? C_DIM : C_TEXT, d->name);
    dk_text(ctx, F_SM14, tx + dk_w(F_SM14, d->name), ty,
            lapsed ? C_FADE3 : C_ACCENT, APP_DOT_TLD);
    if (lapsed) {
        float bw = dk_badge_w(TR(S_DISC_LAPSED));
        struct nk_rect br = nk_rect(tx, ty + 22, bw, 15);
        nk_stroke_rect(dk_cv(ctx), br, 4, 1.0f, C_TINT_RED_BR);
        dk_text_sp(ctx, F_SMB9, br.x + 8, br.y + 2, C_RED, TR(S_DISC_LAPSED), 1);
        return;                                   // no description line
    }

    // description: _site TXT (2-line clamp) / honest placeholders
    float dy = ty + 20;
    if (d->site[0]) {
        dk_clip_push(ctx, nk_rect(tx, dy - 2, tw, 36));
        dk_wrap(ctx, F_PH12, tx, dy, tw, C_DIM, d->site, 1.25f);
        dk_clip_pop(ctx);
    } else if (!d->has_a) {
        dk_clip_push(ctx, nk_rect(tx, dy - 2, tw, 36));
        dk_wrap(ctx, F_PH12, tx, dy, tw, C_DIM, TR(S_DISC_NOSITE), 1.25f);
        dk_clip_pop(ctx);
    } else {
        dk_text(ctx, F_SM10, tx, dy + 2, C_GHOST, TR(S_DISC_NODESC));
    }

    if (servable && hot) sapp_set_mouse_cursor(SAPP_MOUSECURSOR_POINTING_HAND);
    if (servable && dk_click(ctx, r)) {
        if (web_ready) visit(d->name);
        else UI.dialog = DLG_CONSENT;             // 9h carries the missing piece
    }
}

void view_discover(struct nk_context *ctx, struct nk_rect area) {
    // the tab strip is the header — this view opens straight on the search
    float hy = area.y;
    struct nk_rect sr = nk_rect(area.x + 16, hy + 12, area.w - 32, 32);
    dk_card(ctx, sr, 8, C_INPUT, C_BORDER);
    dk_text(ctx, F_SM13, sr.x + 10, sr.y + 9, C_GHOST, "\xE2\x8C\x95");
    struct nk_rect se = nk_rect(sr.x + 26, sr.y + 1, sr.w - 34, sr.h - 2);
    ui_edit(ctx, se, UI.dir_q, &UI.dir_q_len, sizeof UI.dir_q - 1,
            TR(S_DISC_SEARCH_PH), F_SM13, 1);
    UI.dir_q[UI.dir_q_len] = 0;

    struct nk_rect view = nk_rect(area.x, hy + 54, area.w, area.h - 54);

    static DirRow rows[DIR_MAX];
    int64_t built_at = 0; int last_ms = 0;
    int n = M.demo ? 0 : dirscan_snapshot(rows, DIR_MAX, &built_at, &last_ms);

    if (M.demo || built_at == 0) {
        struct nk_rect r = nk_rect(view.x + 16, view.y + 16, view.w - 32, 74);
        dk_rect_dashed(ctx, r, 12, C_BORDER);
        if (M.demo)
            dk_text_c(ctx, F_PH14, r, C_DIM, TR(S_DISC_EMPTY_DEMO));
        else if (M.synced)
            dk_text_c(ctx, F_PH14, r, C_DIM, TR(S_DISC_SCANNING));
        else
            dk_text_c(ctx, F_PH14, r, C_DIM, TR(S_DISC_SCAN_CHAIN));
        return;
    }

    const InstallState *is = inst_state();
    int web_ready = M.web.running && M.dns.resolver_running &&
                    is->ca_trusted && is->resolver_file && is->pf_anchor;
    // favicon fetches ride the DANE proxy — only meaningful once it's up
    if (!M.demo && M.web.running) favicon_boot();

    dk_scroll_begin(ctx, &UI.sc_dir, view);
    float x = view.x + 16, xr = view.x + view.w - 16;
    float y = view.y + 4 - UI.sc_dir.scroll;
    int cols = (int)((xr - x + 12) / (200 + 12));
    if (cols < 2) cols = 2;
    if (cols > 4) cols = 4;
    float cw = (xr - x - (cols - 1) * 12) / cols;

    int shown = 0, sites = 0;
    for (int i = 0; i < n; i++) {
        if (rows[i].has_a && rows[i].has_tlsa && rows[i].registered) sites++;
        if (UI.dir_q_len && !q_match(&rows[i], UI.dir_q)) continue;
        struct nk_rect cr = nk_rect(x + (shown % cols) * (cw + 12),
                                    y + (float)(shown / cols) * (CARD_H + 12),
                                    cw, CARD_H);
        card(ctx, cr, &rows[i], web_ready);
        shown++;
    }
    if (shown)
        y += (float)((shown + cols - 1) / cols) * (CARD_H + 12);
    else {
        dk_text_c(ctx, F_PH14, nk_rect(x, y + 10, xr - x, 30), C_GHOST,
                  UI.dir_q_len ? TR(S_DISC_NOMATCH)
                               : TR(S_DISC_NOZONES));
        y += 46;
    }
    // footer: honest scan cost
    char foot[96];
    snprintf(foot, sizeof foot, TR(S_DISC_FOOT_FMT),
             sites, sites == 1 ? "" : "s", last_ms);
    dk_text(ctx, F_SM9, x + 2, y + 2, C_GHOST, foot);
    y += 22;
    dk_scroll_end(ctx, &UI.sc_dir, view, (y + UI.sc_dir.scroll) - view.y, 0);
}
