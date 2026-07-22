// ui.c — frame entry: background, titlebar, tab strip, view routing, overlays.
#include "ui.h"
#include "../ops.h"

#include "../../vendor/sokol/sokol_app.h"

#include <stdio.h>
#include <string.h>

Ui UI;

void dk_lock_input(int lock);

// ── the tab strip (under the titlebar) ───────────────────────────────────────
// Three sections (9a): Discover · My Names · Name Market. The balance chip at
// the right end drops down the wallet verbs + health rows + Settings. Non-tab
// views (Send/Receive/Settings, per-name DNS/SSL) keep the strip visible but
// light no tab — their headers carry the way back.
#define TAB_H 43
static void tab_strip(struct nk_context *ctx, float W, float y0) {
    static const struct { StrId label; View v; } TABS[] = {
        { S_TAB_DISCOVER, V_DISCOVER },
        { S_TAB_NAMES,    V_NAMES },
        { S_TAB_MARKET,   V_MARKET },
    };
    float x = 28;
    // the per-name screens light My Names — that's where they live
    View lit = (UI.view == V_DNS || UI.view == V_SSL) ? V_NAMES : UI.view;
    for (int i = 0; i < 3; i++) {
        float w = dk_w(F_PH18, TR(TABS[i].label));
        struct nk_rect r = nk_rect(x - 12, y0, w + 24, TAB_H);
        int active = lit == TABS[i].v;
        int hot = !active && dk_hot(ctx, r);
        dk_text(ctx, F_PH18, x, y0 + 10, active ? C_TEXT : hot ? C_ACCENT : C_DIM,
                TR(TABS[i].label));
        if (active)
            dk_fill(ctx, nk_rect(x - 4, y0 + TAB_H - 2, w + 8, 2), 0, C_ACCENT);
        if (hot) sapp_set_mouse_cursor(SAPP_MOUSECURSOR_POINTING_HAND);
        if (dk_click(ctx, r)) { UI.view = TABS[i].v; UI.popup = POP_NONE; }
        x += w + 34;
    }
    if (ui_balance_chip(ctx, W - 16, y0 + TAB_H / 2))
        ui_popup_open(POP_BALANCE, UI.pop_anchor);
    dk_hline(ctx, 0, W, y0 + TAB_H, C_BORDER);
}

// ── the status footer (9a-9h: dedicated strip under the views) ───────────────
// Left: the live-op readout (BUSY/pending run free; DONE/FAIL hold ~6 s then
// self-ack), else a web-health warning, else "idle". Right: sync pulse dot +
// tip height. Views get area minus SB_H, so the readout never covers content.
#define SB_H 24
static void status_bar(struct nk_context *ctx, float W, float H) {
    float by = H - SB_H;
    dk_fill(ctx, nk_rect(0, by, W, SB_H), 0, C_FOOTER);
    dk_hline(ctx, 0, W, by, C_HAIR);

    // right: chain pulse (live) — drawn first so the op line can yield to it
    char rline[64];
    rline[0] = 0;
    struct nk_color rdot = C_GREEN;
    if (M.demo) {
        snprintf(rline, sizeof rline, "%s", TR(S_FOOT_DEMO_DATA));
        rdot = C_GHOST;
    } else if (M.unreachable) {
        snprintf(rline, sizeof rline, "%s", TR(S_FOOT_UNREACHABLE));
        rdot = C_RED;
    } else if (M.height > 0) {
        char hb[32];
        fmt_thousands(hb, sizeof hb, M.height);
        snprintf(rline, sizeof rline, "%s \xC2\xB7 %s",
                 M.synced ? TR(S_SYNC_SYNCED) : TR(S_SYNC_SYNCING), hb);
        rdot = M.synced ? C_GREEN : C_ACCENT;
    } else {
        snprintf(rline, sizeof rline, "%s", TR(S_SYNC_SYNCING));
        rdot = C_ACCENT;
    }
    float rw = rline[0] ? dk_w(F_SM10, rline) + 14 : 0;
    if (rline[0]) {
        dk_text_r(ctx, F_SM10, W - 12, by + 6,
                  M.unreachable ? C_RED : C_GHOST, rline);
        dk_dot(ctx, W - 12 - dk_w(F_SM10, rline) - 9, by + SB_H / 2, 6, rdot);
    }

    // incoming (unconfirmed relay-mempool credits): a chip just left of the chain
    // pulse. Flashes olive for ~6 s when a new payment lands, then steady-dim
    // while it stays pending; clears once the tx confirms into the balance.
    static int64_t inc_prev = -1;
    static int inc_flash;
    if (!M.demo && M.incoming > 0) {
        if (inc_prev >= 0 && M.incoming > inc_prev) inc_flash = 360;   // rose → emphasize
        char amt[48], iline[80];
        fmt_amount_p(amt, sizeof amt, M.incoming);
        snprintf(iline, sizeof iline, TR(S_FOOT_INCOMING_FMT), amt);
        dk_text_r(ctx, F_SM10, W - 12 - (rw ? rw : 0), by + 6,
                  inc_flash > 0 ? C_GREEN : C_FADE3, iline);
        rw += dk_w(F_SM10, iline) + 16;      // reserve room so the op line elides around it
    }
    if (inc_flash > 0) inc_flash--;
    inc_prev = M.demo ? -1 : M.incoming;

    if (M.demo) return;

    // left: op readout > web-health warning > idle
    OpsStatus st;
    ops_status(&st);
    static int hold;                    // frames left on a DONE/FAIL readout
    char line[256];
    struct nk_color col = C_DIM;
    int idle = 0, warn = 0;
    if (st.phase == OPS_BUSY) {
        snprintf(line, sizeof line, TR(S_FOOT_BUSY_FMT), st.label);
        hold = 0;
    } else if (st.phase == OPS_DONE) {
        if (st.dry)
            snprintf(line, sizeof line, TR(S_FOOT_DRYRUN_FMT), st.label);
        else if (st.accepted < 0)   // pushed, but the peer never echoed it back
            snprintf(line, sizeof line, TR(S_FOOT_SENT_NOECHO_FMT), st.label, st.txid);
        else
            snprintf(line, sizeof line, TR(S_FOOT_SENT_FMT), st.label, st.txid);
        col = C_GREEN;
        if (!hold) hold = 360;
    } else if (st.phase == OPS_FAIL) {
        snprintf(line, sizeof line, "\xE2\x9C\x97 %s — %s", st.label, st.err);
        col = C_RED;
        if (!hold) hold = 600;          // errors linger longer
    } else if (st.pending || st.queued) {
        if (st.hold[0])
            snprintf(line, sizeof line, TR(S_FOOT_INFLIGHT_HOLD_FMT),
                     st.inflight, st.queued, st.hold);
        else if (st.queued)
            snprintf(line, sizeof line, TR(S_FOOT_INFLIGHT_QUEUED_FMT),
                     st.inflight, st.queued);
        else
            snprintf(line, sizeof line, TR(S_FOOT_INFLIGHT_FMT),
                     st.inflight, st.inflight == 1 ? "" : "s");
        hold = 0;
    } else if (st.claim_wait) {
        snprintf(line, sizeof line, "%s", TR(S_FOOT_CLAIM_WAIT));
        hold = 0;
    } else if (st.settle_wait) {
        snprintf(line, sizeof line, "%s", TR(S_FOOT_SETTLE_WAIT));
        hold = 0;
    } else {
        hold = 0;
        // no op in flight: surface a web-health warning (9a), else idle
        if (M.dns.running && (!M.dns.resolver_running || !M.web.running)) {
            snprintf(line, sizeof line, TR(S_FOOT_WEB_DEGRADED_FMT),
                     !M.dns.resolver_running ? TR(S_FOOT_RESOLVER_DOWN) : TR(S_FOOT_PROXY_DOWN));
            col = C_RED;
            warn = 1;
        } else {
            snprintf(line, sizeof line, "%s", TR(S_FOOT_IDLE));
            col = C_GHOST;
            idle = 1;
        }
    }
    if (st.phase == OPS_DONE || st.phase == OPS_FAIL) {
        if (--hold <= 0) { ops_ack(); hold = 0; }
    }
    // elide the op line so it never runs under the chain pulse
    float lx = 12;
    if (!idle) {
        dk_dot(ctx, lx + 3, by + SB_H / 2, 6, warn ? C_RED : C_ACCENT);
        lx += 14;
    }
    float avail = W - lx - 12 - (rw ? rw + 24 : 0);
    if (dk_w(F_SM10, line) > avail) {
        char probe[256];
        int len = (int)strlen(line);
        do {
            len -= 2;
            while (len > 0 && ((unsigned char)line[len] & 0xC0) == 0x80)
                len--;                  // never cut a UTF-8 sequence
            snprintf(probe, sizeof probe, "%.*s\xE2\x80\xA6", len, line);
        } while (len > 4 && dk_w(F_SM10, probe) > avail);
        snprintf(line, sizeof line, "%s", probe);
    }
    dk_text(ctx, F_SM10, lx, by + 6, col, line);
}

void ui_frame(struct nk_context *ctx, float W, float H) {
    dk_frame_begin(ctx);
    struct nk_rect screen = nk_rect(0, 0, W, H);

    // first-run backup nag, queued by init(): wait for a clear stage so it
    // never stacks over consent/lock (or anything else), then show once
    if (UI.backup_pending && UI.dialog == DLG_NONE && UI.popup == POP_NONE) {
        UI.backup_pending = 0;
        UI.dialog = DLG_BACKUP;
    }

    if (nk_begin(ctx, "pepenet", screen, NK_WINDOW_BACKGROUND | NK_WINDOW_NO_SCROLLBAR)) {
        nk_layout_space_begin(ctx, NK_STATIC, H, 256);
        dk_fill(ctx, screen, 0, C_BG);

        // 38px titlebar strip — native traffic lights float over the left edge;
        // we draw the centered brand and the hairline (mockup titlebar).
        dk_text_c(ctx, F_PH16, nk_rect(0, 0, W, 37), C_DIM, APP_NAME);
        if (M.demo)
            dk_text_r(ctx, F_SM9, W - 12, 14, C_GHOST, TR(S_FOOT_DEMO_DATA));
        dk_hline(ctx, 0, W, 37, C_HAIR);

        // remember the tab so the dropdown views' ‹ back knows where home was
        if (UI.view == V_DISCOVER || UI.view == V_NAMES || UI.view == V_MARKET)
            UI.last_tab = UI.view;

        struct nk_rect area = nk_rect(0, 38 + TAB_H + 1, W, H - 38 - TAB_H - 1 - SB_H);

        // widgets under an open popup/dialog must not react
        dk_lock_input(UI.dialog != DLG_NONE || UI.popup != POP_NONE);
        tab_strip(ctx, W, 38);
        switch (UI.view) {
            case V_NAMES:    view_names(ctx, area); break;
            case V_MARKET:   view_market(ctx, area); break;
            case V_RECEIVE:  view_receive(ctx, area); break;
            case V_SEND:     view_send(ctx, area); break;
            case V_DNS:      view_dns(ctx, area); break;
            case V_SSL:      view_ssl(ctx, area); break;
            case V_PEERS:    view_peers(ctx, area); break;
            case V_SETTINGS: view_settings(ctx, area); break;
            default:         view_discover(ctx, area); break;
        }
        dk_lock_input(0);

        status_bar(ctx, W, H);
        if (UI.popup != POP_NONE) popups_draw(ctx, screen);
        // a dialog's FIRST frame draws with input locked: the click that just
        // opened (or switched) it is still live in this frame's input state,
        // so any dialog button sitting under that same point would fire on
        // the spot (press "Reveal recovery phrase" in the wrong place and the
        // dialog's own button instantly closes it). One locked frame kills
        // the carry-over; the guard resets whenever the dialog slot empties.
        static Dialog dlg_last;
        int dlg_fresh = UI.dialog != DLG_NONE && UI.dialog != dlg_last;
        dlg_last = UI.dialog;
        if (UI.dialog != DLG_NONE) {
            if (dlg_fresh) dk_lock_input(1);
            dialogs_draw(ctx, screen);
            if (dlg_fresh) dk_lock_input(0);
        }

        nk_layout_space_end(ctx);
    }
    nk_end(ctx);
}
