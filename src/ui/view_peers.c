// view_peers.c — the Peers screen (balance dropdown → Peers): the live serve
// loop's connection table and the chain-walk (crawl) monitor. Two data
// sources, both read-only:
//   connections — idx_serve_conns(), the serve loop's ~1 Hz seqlock snapshot
//                 (the same connections the DNS mesh gossips over);
//   chain walk  — idx_crawl_status(), live progress of the crawl that walks
//                 the host chain's peer graph until discovery-marked peers turn up.
#include "ui.h"
#include "../engine.h"      // engine_crawl_start/stop — the walk is operator-driven
#include "indexer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// coarse relative age: "34s" / "5m" / "2h" / "3d"
static void fmt_ago(char *out, size_t cap, int64_t secs) {
    if (secs < 0) secs = 0;
    if (secs < 60)         snprintf(out, cap, "%llds", (long long)secs);
    else if (secs < 3600)  snprintf(out, cap, "%lldm", (long long)(secs / 60));
    else if (secs < 86400) snprintf(out, cap, "%lldh", (long long)(secs / 3600));
    else                   snprintf(out, cap, "%lldd", (long long)(secs / 86400));
}

static int is_marked(const char *agent) {   // IDX_DNET_MARK = "/pepenet-" here
    return strncmp(agent, IDX_DNET_MARK, sizeof IDX_DNET_MARK - 1) == 0;
}

// connected + up first, then handshaking, then redialing slots
static int conn_cmp(const void *a, const void *b) {
    const IdxServeConn *x = a, *y = b;
    int rx = x->connected ? (x->up ? 0 : 1) : 2;
    int ry = y->connected ? (y->up ? 0 : 1) : 2;
    if (rx != ry) return rx - ry;
    return strcmp(x->peer, y->peer);
}

// small outlined chip (the DNS screen's type chip); returns width consumed
static float chip(struct nk_context *ctx, float x, float y, const char *s,
                  struct nk_color col) {
    float w = dk_w(F_SMB10, s) + 14;
    struct nk_rect r = nk_rect(x, y, w, 18);
    nk_stroke_rect(dk_cv(ctx), r, 4, 1.0f, C_BORDER);
    dk_text_c(ctx, F_SMB10, r, col, s);
    return w;
}

// fit `s` into maxw px of font f — truncate at a utf8 boundary + trailing …
static void fit_ellipsis(ThemeFont f, float maxw, const char *s,
                         char *out, size_t cap) {
    size_t n = strlen(s);
    if (n >= cap) n = cap - 1;
    memcpy(out, s, n); out[n] = 0;
    if (dk_w(f, out) <= maxw) return;
    while (n > 0) {
        n--;
        while (n > 0 && ((unsigned char)s[n] & 0xC0) == 0x80) n--;
        memcpy(out, s, n);
        snprintf(out + n, cap - n, "\xE2\x80\xA6");
        if (dk_w(f, out) <= maxw) return;
    }
}

void view_peers(struct nk_context *ctx, struct nk_rect area) {
    ui_screen_header(ctx, area, TR(S_PEERS_TITLE));
    if (M.demo) {
        struct nk_rect r = nk_rect(area.x + 40, area.y + 80, area.w - 80, 62);
        dk_rect_dashed(ctx, r, 12, C_BORDER);
        dk_text_c(ctx, F_PH16, r, C_DIM, TR(S_PEERS_EMPTY_DEMO));
        return;
    }

    // live snapshots — lock-free copies, cheap enough per frame
    IdxServeConn conns[64];
    int nc = idx_serve_conns(conns, 64);
    qsort(conns, (size_t)nc, sizeof conns[0], conn_cmp);
    IdxCrawlStatus cw;
    idx_crawl_status(&cw);

    struct nk_rect view = nk_rect(area.x, area.y + 56, area.w, area.h - 56);
    dk_scroll_begin(ctx, &UI.sc_peers, view);
    float x = view.x + 16, xr = view.x + view.w - 16;
    float y = view.y + 14 - UI.sc_peers.scroll;
    char b[192];
    float head_h = 42, cols_h = 26, row_h = 30;

    // ── connections: the serve loop's live table ──────────────────────────────
    int nup = 0, nmesh = 0, nmarked = 0;
    for (int i = 0; i < nc; i++) {
        if (conns[i].connected && conns[i].up) {
            nup++;
            if (is_marked(conns[i].agent)) nmarked++;
        }
        if (conns[i].mesh) nmesh++;
    }
    {
        float body_h = nc > 0 ? nc * row_h : 44;
        struct nk_rect card = nk_rect(x, y, xr - x, head_h + cols_h + body_h + 10);
        dk_card(ctx, card, 10, C_PANEL, C_BORDER);

        dk_text(ctx, F_PH16, x + 14, y + 9, C_TEXT, TR(S_PEERS_CONNS_HDR));
        snprintf(b, sizeof b, TR(S_PEERS_CONNS_FMT), nup, nmesh);
        dk_text(ctx, F_SM10, x + 14 + dk_w(F_PH16, TR(S_PEERS_CONNS_HDR)) + 10,
                y + 14, C_GHOST, b);
        dk_hline(ctx, x + 1, xr - 1, y + head_h, C_BORDER);
        y += head_h;

        float cx_peer = x + 30, cx_dir = x + 208, cx_agent = x + 258;
        float cx_state = xr - 14;
        dk_text_sp(ctx, F_SM9, cx_peer, y + 8, C_GHOST, TR(S_PEERS_COL_PEER), 1);
        dk_text_sp(ctx, F_SM9, cx_agent, y + 8, C_GHOST, TR(S_PEERS_COL_AGENT), 1);
        dk_text_sp(ctx, F_SM9, cx_state - dk_w_sp(F_SM9, TR(S_PEERS_COL_STATE), 1),
                   y + 8, C_GHOST, TR(S_PEERS_COL_STATE), 1);
        dk_hline(ctx, x + 1, xr - 1, y + cols_h, C_HAIR);
        y += cols_h;

        if (nc == 0) {
            dk_text_c(ctx, F_PH12, nk_rect(x, y, xr - x, 44), C_GHOST,
                      TR(S_PEERS_CONNS_EMPTY));
            y += 44;
        }
        for (int i = 0; i < nc; i++) {
            IdxServeConn *c = &conns[i];
            int dn = is_marked(c->agent);
            if (dn) dk_fill(ctx, nk_rect(x + 1, y, xr - x - 2, row_h), 0, HEXC(0x1C1E17));

            // status dot + peer addr (a redialing slot shows its dial target)
            char state[48];
            struct nk_color dot, stc;
            if (c->connected && c->up) {
                snprintf(state, sizeof state, "%s", TR(S_PEERS_ST_UP));
                dot = stc = C_GREEN;
            } else if (c->connected) {
                snprintf(state, sizeof state, "%s", TR(S_PEERS_ST_HANDSHAKE));
                dot = stc = C_ACCENT;
            } else if (c->redial_in > 0) {
                snprintf(state, sizeof state, TR(S_PEERS_ST_REDIAL_FMT),
                         (long long)c->redial_in);
                dot = stc = C_GHOST;
            } else {
                snprintf(state, sizeof state, "%s", TR(S_PEERS_ST_DIALING));
                dot = stc = C_ACCENT;
            }
            dk_dot(ctx, x + 17, y + row_h / 2, 6, dot);
            char peer[96];
            if (c->peer[0]) snprintf(peer, sizeof peer, "%s", c->peer);
            else            snprintf(peer, sizeof peer, "%s:%u", c->host, c->rport);
            dk_clip_push(ctx, nk_rect(cx_peer, y, cx_dir - cx_peer - 8, row_h));
            dk_text(ctx, F_SM13, cx_peer, y + 7, c->connected ? C_TEXT : C_DIM, peer);
            dk_clip_pop(ctx);

            chip(ctx, cx_dir, y + 6,
                 c->outbound ? TR(S_PEERS_DIR_OUT) : TR(S_PEERS_DIR_IN),
                 c->outbound ? C_DIM : C_ACCENT);

            // agent, ellipsis-trimmed so badges + state stay readable
            float agent_r = cx_state - dk_w(F_SM11, state) - 12;
            float bx = agent_r;
            if (c->mesh)      bx -= dk_badge_w(TR(S_PEERS_BADGE_MESH)) + 6;
            if (c->mesh_seat) bx -= dk_badge_w(TR(S_PEERS_BADGE_SEAT)) + 6;
            if (c->agent[0]) {
                char ag[128];
                fit_ellipsis(F_SM11, bx - cx_agent - 8, c->agent, ag, sizeof ag);
                dk_text(ctx, F_SM11, cx_agent, y + 8, dn ? C_GREEN : C_DIM, ag);
            } else if (c->connected)
                dk_text(ctx, F_SM11, cx_agent, y + 8, C_GHOST, TR(S_PEERS_NO_AGENT));
            float badge_x = bx;
            if (c->mesh)
                badge_x += dk_badge(ctx, badge_x, y + 7, TR(S_PEERS_BADGE_MESH),
                                    BADGE_LINE_GREEN) + 6;
            if (c->mesh_seat)
                dk_badge(ctx, badge_x, y + 7, TR(S_PEERS_BADGE_SEAT), BADGE_LINE_ACCENT);
            dk_text_r(ctx, F_SM11, cx_state, y + 8, stc, state);

            if (i < nc - 1) dk_hline(ctx, x + 1, xr - 1, y + row_h, C_HAIR);
            y += row_h;
        }
        y += 10 + 12;
    }

    // ── chain walk: the discovery-mark hunt over the host chain's peer graph ──
    {
        float kv = 22 * 4;
        struct nk_rect card = nk_rect(x, y, xr - x, head_h + 8 + kv + 10);
        dk_card(ctx, card, 10, C_PANEL, C_BORDER);

        dk_text(ctx, F_PH16, x + 14, y + 9, C_TEXT, TR(S_PEERS_WALK_HDR));
        // operator control: the walk never runs on its own. Stop while a walk
        // is queued/on the wire; Start otherwise — greyed (and refused by the
        // engine) while any pepenet peer is connected, because the walk's only
        // job is finding one.
        { int busy = engine_crawl_busy() || cw.running;
          int gated = nmarked > 0;
          struct nk_rect br = nk_rect(xr - 96, y + 8, 82, 26);
          if (busy) {
              if (dk_btn(ctx, br, F_SM13, TR(S_PEERS_WALK_STOP), BTN_LINE))
                  engine_crawl_stop();
              dk_dot(ctx, br.x - 14, y + head_h / 2, 6, C_ACCENT);
          } else if (gated) {
              dk_btn_col(ctx, br, F_SM13, TR(S_PEERS_WALK_START), BTN_LINE, C_GHOST);
          } else if (dk_btn(ctx, br, F_SM13, TR(S_PEERS_WALK_START), BTN_LINE)) {
              engine_crawl_start();
          } }
        dk_hline(ctx, x + 1, xr - 1, y + head_h, C_BORDER);
        y += head_h + 8;

        float kx = x + 14, kxr = xr - 14;
        if (cw.running)
            snprintf(b, sizeof b, TR(S_PEERS_WALK_LIVE_FMT), cw.dials, cw.max_dials);
        else if (engine_crawl_busy())
            snprintf(b, sizeof b, "%s", TR(S_PEERS_WALK_QUEUED));
        else if (nmarked > 0)
            snprintf(b, sizeof b, "%s", TR(S_PEERS_WALK_GATED));
        else if (cw.last_pass == 0)
            snprintf(b, sizeof b, "%s", TR(S_PEERS_WALK_NEVER));
        else
            snprintf(b, sizeof b, "%s", TR(S_PEERS_WALK_IDLE));
        ui_kv_row(ctx, kx, kxr, y, TR(S_PEERS_WALK_STATUS), b,
                  C_GHOST, cw.running ? C_ACCENT : C_DIM);
        y += 22;

        snprintf(b, sizeof b, TR(S_PEERS_WALK_PASS_FMT), cw.dials, cw.up, cw.hits);
        ui_kv_row(ctx, kx, kxr, y, TR(S_PEERS_WALK_PASS), b, C_GHOST,
                  cw.hits > 0 ? C_GREEN : C_DIM);
        y += 22;

        if (cw.last_peer[0])
            snprintf(b, sizeof b, "%s \xC2\xB7 %s", cw.last_peer,
                     cw.last_agent[0] ? cw.last_agent : TR(S_PEERS_WALK_DOWN));
        else
            b[0] = 0;
        ui_kv_row(ctx, kx, kxr, y, TR(S_PEERS_WALK_PROBE), b, C_GHOST,
                  is_marked(cw.last_agent) ? C_GREEN : C_DIM);
        y += 22;

        if (cw.last_pass > 0) {
            char ago[24];
            fmt_ago(ago, sizeof ago, M.now - cw.last_pass);
            snprintf(b, sizeof b, TR(S_PEERS_WALK_LAST_FMT), ago, (long long)cw.passes);
        } else {
            snprintf(b, sizeof b, "\xE2\x80\x94");
        }
        ui_kv_row(ctx, kx, kxr, y, TR(S_PEERS_WALK_LAST), b, C_GHOST, C_DIM);
        y += 22;
        y += 10 + 12;
    }

    y += 14;
    dk_scroll_end(ctx, &UI.sc_peers, view, (y + UI.sc_peers.scroll) - view.y, 0);
}
