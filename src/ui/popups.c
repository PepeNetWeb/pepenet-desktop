// popups.c — anchored dropdown panels. The sections live on the tab strip;
// the balance chip drops down the wallet verbs + the live health rows +
// Settings (9a); the My Names selection bar's "···" carries the batch
// overflow (Transfer N / Release N, 9b).
#include "ui.h"

#include "../../vendor/sokol/sokol_app.h"

#include <stdio.h>
#include <string.h>

static int menu_row(struct nk_context *ctx, struct nk_rect r, ThemeFont f,
                    struct nk_color tcol, const char *label) {
    int hot = dk_hot(ctx, r);
    if (hot) {
        dk_fill(ctx, r, 7, C_INPUT);
        sapp_set_mouse_cursor(SAPP_MOUSECURSOR_POINTING_HAND);
    }
    dk_text(ctx, f, r.x + 12, r.y + (r.h - theme_lineh(f)) / 2, tcol, label);
    return dk_click(ctx, r);
}

static void panel_frame(struct nk_context *ctx, struct nk_rect r) {
    dk_card(ctx, r, 10, HEXC(0x1D1F18), HEXC(0x464A38));
}

// place below the anchor, right-aligned to it; flip above if it would clip
static struct nk_rect anchored(struct nk_rect anchor, float w, float h,
                               struct nk_rect screen, int align_right) {
    float x = align_right ? anchor.x + anchor.w - w : anchor.x;
    if (x < 8) x = 8;
    if (x + w > screen.w - 8) x = screen.w - 8 - w;
    float y = anchor.y + anchor.h + 6;
    if (y + h > screen.h - 8) y = anchor.y - h - 6;
    if (y < 44) y = 44;
    return nk_rect(x, y, w, h);
}

// one k/v health row (keys ghost, values colored by state)
static void health_row(struct nk_context *ctx, float x, float xr, float y,
                       const char *k, const char *v, struct nk_color vc) {
    dk_text(ctx, F_SM10, x, y, C_GHOST, k);
    dk_text_r(ctx, F_SM10, xr, y, vc, v);
}

// ── 9a: balance dropdown — balance · verbs · health · Settings ───────────────
static struct nk_rect pop_balance(struct nk_context *ctx, struct nk_rect screen) {
    float w = 258;
    int webrows = M.demo ? 0 : 1;
    float head = 74, verbs = 52;
    float rows = 18 * 2 + (webrows ? 9 + 18 * 3 : 0);
    float foot = webrows ? 76 : 43;         // + the Peers row (live only)
    float h = head + verbs + 9 + rows + 9 + foot + 4;
    struct nk_rect p = anchored(UI.pop_anchor, w, h, screen, 1);
    panel_frame(ctx, p);
    char b[64];

    float y = p.y + 12;
    dk_text_sp(ctx, F_SM9, p.x + 14, y, C_GHOST, TR(S_POP_BALANCE), 1);
    fmt_amount_p(b, sizeof b, M.balance);
    dk_text(ctx, F_SM22, p.x + 14, y + 14, C_TEXT, b);
    fmt_addr_short(b, sizeof b, M.address[0] ? M.address : TR(S_POP_NOWALLET));
    dk_text(ctx, F_SM10, p.x + 14, y + 44, C_GHOST, b);
    dk_hline(ctx, p.x + 8, p.x + p.w - 8, y + head - 10, C_BORDER);
    y += head;

    // Receive | Send (bordered = safe verbs)
    float bw = (p.w - 28 - 8) / 2;
    if (dk_btn_col(ctx, nk_rect(p.x + 14, y, bw, 32), F_PH14, TR(S_POP_RECEIVE),
                   BTN_LINE_FILL, C_TEXT)) {
        UI.view = V_RECEIVE; UI.popup = POP_NONE;
    }
    if (dk_btn_col(ctx, nk_rect(p.x + 14 + bw + 8, y, bw, 32), F_PH14, TR(S_POP_SEND),
                   BTN_LINE_FILL, C_TEXT)) {
        UI.view = V_SEND; UI.popup = POP_NONE;
    }
    y += verbs;
    dk_hline(ctx, p.x + 8, p.x + p.w - 8, y - 5, C_BORDER);
    y += 6;

    float x = p.x + 14, xr = p.x + p.w - 14;
    // sync + rent
    if (M.demo) {
        health_row(ctx, x, xr, y, TR(S_POP_SYNC), TR(S_FOOT_DEMO_DATA), C_GHOST);
    } else if (M.unreachable) {
        health_row(ctx, x, xr, y, TR(S_POP_SYNC), TR(S_FOOT_UNREACHABLE), C_RED);
    } else {
        char hb[32], sv[48];
        fmt_thousands(hb, sizeof hb, M.height);
        snprintf(sv, sizeof sv, "%s \xC2\xB7 %s",
                 M.synced ? TR(S_SYNC_SYNCED) : TR(S_SYNC_SYNCING), hb);
        health_row(ctx, x, xr, y, TR(S_POP_SYNC), sv, M.synced ? C_GREEN : C_ACCENT);
    }
    y += 18;
    {
        char ra[32], rb[48];
        fmt_amount(ra, sizeof ra, M.year_cost);
        snprintf(rb, sizeof rb, TR(S_POP_RENT_FMT), ra);
        health_row(ctx, x, xr, y, TR(S_POP_RENT_RATE), rb, C_DIM);
        y += 18;
    }
    if (webrows) {
        dk_hline(ctx, x, xr, y + 2, C_BORDER);
        y += 9;
        if (M.dns.running)
            snprintf(b, sizeof b, TR(S_POP_NCONN_FMT), M.dns.peers);
        else
            snprintf(b, sizeof b, "%s", TR(S_POP_STARTING));
        health_row(ctx, x, xr, y, TR(S_POP_MESH_PEERS), b,
                   M.dns.running && M.dns.peers > 0 ? C_GREEN : C_GHOST);
        y += 18;
        if (M.dns.resolver_running)
            snprintf(b, sizeof b, TR(S_POP_PORT_UP_FMT), M.dns.resolver_port);
        else
            snprintf(b, sizeof b, "%s", TR(S_POP_NOT_RESPONDING));
        health_row(ctx, x, xr, y, TR(S_POP_RESOLVER), b,
                   M.dns.resolver_running ? C_GREEN : C_RED);
        y += 18;
        if (M.web.running)
            snprintf(b, sizeof b, TR(S_POP_PORT_UP_FMT), M.web.port);
        else
            snprintf(b, sizeof b, "%s", TR(S_POP_DOWN));
        health_row(ctx, x, xr, y, TR(S_POP_PROXY), b, M.web.running ? C_GREEN : C_RED);
        y += 18;
    }
    dk_hline(ctx, p.x + 8, p.x + p.w - 8, y + 4, C_BORDER);
    y += 9;
    if (webrows) {
        if (menu_row(ctx, nk_rect(p.x + 6, y, p.w - 12, 32), F_PH16, C_TEXT, TR(S_PEERS_TITLE))) {
            UI.view = V_PEERS;
            UI.popup = POP_NONE;
        }
        y += 33;
    }
    if (menu_row(ctx, nk_rect(p.x + 6, y, p.w - 12, 32), F_PH16, C_TEXT, TR(S_POP_SETTINGS))) {
        UI.view = V_SETTINGS;
        UI.popup = POP_NONE;
    }
    return p;
}

// ── 9b: selection-bar overflow — Transfer N / Release N ─────────────────────
static struct nk_rect pop_names_more(struct nk_context *ctx, struct nk_rect screen) {
    int nrel = 0;
    for (int i = 0; i < M.nnames; i++)
        if ((UI.sel_mask >> i) & 1 &&
            M.names[i].st == NS_OWNED && !M.names[i].pending)
            nrel++;
    float w = 156, h = 2 * 38 + 2;
    struct nk_rect p = anchored(UI.pop_anchor, w, h, screen, 1);
    panel_frame(ctx, p);
    char b[32];
    snprintf(b, sizeof b, TR(S_POP_TRANSFER_N_FMT), nrel);
    float y = p.y + 1;
    if (nrel) {
        if (menu_row(ctx, nk_rect(p.x + 4, y, p.w - 8, 36), F_PH14, C_TEXT, b)) {
            UI.dialog = DLG_BATCH_TRANSFER;
            UI.send_to_len = 0;
            UI.popup = POP_NONE;
        }
    } else {
        dk_text(ctx, F_PH14, p.x + 16, y + 9, C_GHOST, b);
    }
    dk_hline(ctx, p.x + 8, p.x + p.w - 8, y + 37, C_BORDER);
    y += 38;
    snprintf(b, sizeof b, TR(S_POP_RELEASE_N_FMT), nrel);
    if (nrel) {
        if (menu_row(ctx, nk_rect(p.x + 4, y, p.w - 8, 36), F_PH14, C_RED, b)) {
            UI.dialog = DLG_BATCH_RELEASE;
            UI.popup = POP_NONE;
        }
    } else {
        dk_text(ctx, F_PH14, p.x + 16, y + 9, C_GHOST, b);
    }
    return p;
}

void popups_draw(struct nk_context *ctx, struct nk_rect screen) {
    // panels close themselves via row handlers; any click that lands outside
    // the drawn panel closes the popup (clicking the trigger again = toggle off)
    struct nk_rect panel;
    switch (UI.popup) {
        case POP_BALANCE:    panel = pop_balance(ctx, screen); break;
        case POP_NAMES_MORE: panel = pop_names_more(ctx, screen); break;
        default: return;
    }
    if (UI.popup == POP_NONE) return;                    // a row already closed it
    if (UI.pop_guard) { UI.pop_guard = 0; return; }      // the click that opened us
    struct nk_input *in = &ctx->input;
    if (nk_input_mouse_clicked(in, NK_BUTTON_LEFT, screen)) {
        struct nk_vec2 mp = in->mouse.pos;
        int in_panel = mp.x >= panel.x && mp.x <= panel.x + panel.w &&
                       mp.y >= panel.y && mp.y <= panel.y + panel.h;
        if (!in_panel) UI.popup = POP_NONE;
    }
}
