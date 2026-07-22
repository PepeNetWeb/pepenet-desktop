// view_screens.c — Names · Market (tabs) · Receive · Send · Settings (balance
// dropdown); Discover (home tab) and DNS & Web live in their own view_*.c
// files. Tab views open straight on content — the tab strip is their header.
#include "ui.h"
#include "../wallet.h"
#include "../ops.h"
#include "../engine.h"
#include "../qr.h"
#include "../dirscan.h"
#include "../sysinstall.h"
#include "../platform.h"     // data dir, folder picker, config seam

#include "../../vendor/sokol/sokol_app.h"
#include "../../vendor/sokol/sokol_gfx.h"
#include "../../vendor/sokol/util/sokol_nuklear.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ═════════════════════════════════ NAMES (9b) ═══════════════════════════════
static int name_renewable(const MyName *n) {
    if (n->st == NS_RESERVED) return 0;
    if (n->st == NS_CLAIMING) return 0;     // not on-chain yet — no lease to top up
    return (365 - (int)((n->expiry - M.now) / 86400)) > 0;
}

// servable lookup against the Discover directory (LIVE badge), cached ~2 s
static DirRow g_ndir[DIR_MAX];
static int g_ndirn;
static int64_t g_ndir_at;
static const DirRow *dir_find(const char *name) {
    if (!M.demo && M.now - g_ndir_at >= 2) {
        g_ndirn = dirscan_snapshot(g_ndir, DIR_MAX, NULL, NULL);
        g_ndir_at = M.now;
    }
    for (int i = 0; i < g_ndirn; i++)
        if (strcmp(g_ndir[i].name, name) == 0) return &g_ndir[i];
    return NULL;
}

// countdown color: the 9b expiry fade — red inside the renew window, then
// dimming steps as the horizon recedes
static struct nk_color expiry_col(int64_t left) {
    if (left < 30LL * 86400) return C_RED;
    if (left < 90LL * 86400) return C_DIM;
    return C_DIM;
}

void view_names(struct nk_context *ctx, struct nk_rect area) {
    char b[96], sub[96];
    float y = area.y;
    float x = area.x + 12, xr = area.x + area.w - 12;

    // header bar (9b): count · filter · + register a name
    {
        int live = 0;
        for (int i = 0; i < M.nnames; i++) {
            const DirRow *d = M.names[i].st != NS_CLAIMING ? dir_find(M.names[i].name) : NULL;
            if (d && d->has_a && d->has_tlsa) live++;
        }
        snprintf(b, sizeof b, TR(S_NAMES_COUNT_FMT),
                 M.nnames, M.nnames == 1 ? "" : "s", live);
        dk_text(ctx, F_SM11, area.x + 18, y + 15, C_GHOST, b);

        float rw2 = dk_w(F_PH14, TR(S_NAMES_REGISTER)) + 30;
        struct nk_rect rb = nk_rect(area.x + area.w - 16 - rw2, y + 7, rw2, 29);
        if (dk_btn(ctx, rb, F_PH14, TR(S_NAMES_REGISTER), BTN_ACCENT)) {
            UI.dialog = DLG_CLAIM;
            UI.claim_name_len = 0;
            UI.claim_days = 365;
        }
        struct nk_rect fr = nk_rect(rb.x - 10 - 150, y + 7, 150, 29);
        dk_card(ctx, fr, 8, C_INPUT, C_BORDER);
        dk_text(ctx, F_SM11, fr.x + 10, fr.y + 8, C_GHOST, "\xE2\x8C\x95");
        ui_edit(ctx, nk_rect(fr.x + 24, fr.y + 1, fr.w - 30, fr.h - 2), UI.names_q,
                &UI.names_q_len, sizeof UI.names_q - 1, TR(S_NAMES_FILTER_PH), F_SM13, 1);
        UI.names_q[UI.names_q_len] = 0;
        dk_hline(ctx, area.x, area.x + area.w, y + 43, C_HAIR);
        y += 44;
    }

    int nsel = 0, nren = 0, nrel = 0;           // selected vs renewable vs releasable
    int64_t est = 0;
    for (int i = 0; i < M.nnames; i++)
        if (UI.sel_mask & (1u << i)) {
            MyName *sn = &M.names[i];
            nsel++;
            if (sn->st == NS_OWNED && !sn->pending) nrel++;
            if (!name_renewable(sn) || sn->pending) continue;
            int add = 365 - (int)((sn->expiry - M.now) / 86400);
            nren++;
            est += M.year_cost * add / 365 + UI_FEE_K;
        }
    float bar_h = nsel ? 56 : 0;
    struct nk_rect view = nk_rect(area.x, y, area.w, area.y + area.h - y - bar_h);

    dk_scroll_begin(ctx, &UI.sc_names, view);
    float ry = view.y + 8 - UI.sc_names.scroll;
    for (int i = 0; i < M.nnames; i++) {
        MyName *n = &M.names[i];
        if (UI.names_q_len && !strstr(n->name, UI.names_q)) continue;
        int sel = (UI.sel_mask >> i) & 1;
        int claiming = n->st == NS_CLAIMING;
        int expanded = !claiming && UI.name_expanded == i;
        int reserved = n->st == NS_RESERVED;
        const DirRow *dr = claiming ? NULL : dir_find(n->name);
        int servable = dr && dr->has_a && dr->has_tlsa;
        float rh = 52 + (expanded ? 38 : 0);
        struct nk_rect row = nk_rect(x, ry, xr - x, rh);
        if (sel || expanded || n->pending) dk_fill(ctx, row, 8, C_PANEL);
        if (expanded) dk_line_rect(ctx, row, 8, C_BORDER);

        // checkbox — feeds the §3.5 bitmap batches (selective renew, batch
        // release); rows already spoken for (reserved, claiming, op queued)
        // don't select
        {
            int pickable = !reserved && !claiming && !n->pending;
            struct nk_rect cb = nk_rect(x + 12, ry + 17, 18, 18);
            if (!pickable) {
                dk_line_rect(ctx, cb, 5, C_HAIR);
            } else if (sel) {
                dk_fill(ctx, cb, 5, C_ACCENT);
                dk_text_c(ctx, F_SM11, cb, C_ONFILL, "\xE2\x9C\x93");
            } else {
                dk_line_rect(ctx, cb, 5, C_GHOST);
            }
            if (pickable && dk_click(ctx, cb)) UI.sel_mask ^= 1u << i;
        }

        // name + accent TLD suffix (9b)
        struct nk_color namec = (reserved || claiming) ? C_DIM : C_TEXT;
        dk_text(ctx, F_SM14, x + 42, ry + 8, namec, n->name);
        dk_text(ctx, F_SM14, x + 42 + dk_w(F_SM14, n->name), ry + 8,
                reserved || claiming ? C_FADE3 : C_ACCENT, APP_DOT_TLD);

        int64_t left = n->expiry - M.now;
        int soon = left < 30LL * 86400;
        if (n->pending && !claiming) {          // the queued op speaks for the row
            const char *pl[] = { "", TR(S_SCR_RENEW), TR(S_SCR_SELL), TR(S_SCR_OFFER),
                                 TR(S_SCR_TRANSFER), TR(S_SCR_RELEASE), TR(S_SCR_CLAIM),
                                 TR(S_NAMES_MARKET_OP) };
            int pi = n->pending > 0 && n->pending <= 7 ? n->pending : 7;
            snprintf(sub, sizeof sub, TR(S_SCR_QUEUED_FMT), pl[pi]);
            dk_text(ctx, F_SM10, x + 42, ry + 28, C_ACCENT, sub);
        } else switch (n->st) {
            case NS_CLAIMING:
                dk_text(ctx, F_SM10, x + 42, ry + 28, C_GHOST,
                        TR(S_NAMES_CLAIMING_SUB));
                break;
            case NS_OWNED:
                if (soon) {
                    fmt_date_short(b, sizeof b, n->expiry);
                    snprintf(sub, sizeof sub, TR(S_NAMES_EXPIRES_SOON_FMT), b);
                    dk_text(ctx, F_SM10, x + 42, ry + 28, C_RED, sub);
                } else {
                    fmt_date_long(b, sizeof b, n->expiry);
                    snprintf(sub, sizeof sub, TR(S_NAMES_EXPIRES_FMT), b);
                    dk_text(ctx, F_SM10, x + 42, ry + 28, C_GHOST, sub);
                }
                break;
            case NS_LISTED: {
                char p[32], wleft[24];
                fmt_amount_sp(p, sizeof p, n->list_price);
                fmt_days_left(wleft, sizeof wleft, n->list_window_end - M.now);
                snprintf(sub, sizeof sub, TR(S_NAMES_LISTED_FMT), p, wleft);
                dk_text(ctx, F_SM10, x + 42, ry + 28, C_DIM, sub);
                break;
            }
            case NS_RESERVED:
                dk_text(ctx, F_SM10, x + 42, ry + 28, C_GHOST, TR(S_NAMES_RESERVED_SUB));
                break;
            default: {
                char p[32];
                fmt_amount_sp(p, sizeof p, n->offer_price);
                snprintf(sub, sizeof sub, TR(S_NAMES_OFFERED_FMT), n->offered_to, p);
                dk_text(ctx, F_SM10, x + 42, ry + 28, C_DIM, sub);
                break;
            }
        }

        // badge + countdown (a claiming row has no lease clock yet)
        char dleft[24];
        if (!claiming) {
            fmt_days_left(dleft, sizeof dleft,
                          n->st == NS_RESERVED || n->st == NS_OFFERED
                              ? n->reserve_end - M.now : left);
            dk_text_r(ctx, F_SM11, xr - 10, ry + 19,
                      n->st == NS_OWNED ? expiry_col(left) : C_DIM, dleft);
        }
        // 9b badge set: LIVE (servable) beats OWNED; a queued op renames it
        BadgeStyle bs = n->st == NS_OWNED ? BADGE_FILL_GREEN
                      : n->st == NS_LISTED ? BADGE_FILL_ACCENT
                      : n->st == NS_RESERVED || n->st == NS_CLAIMING
                          ? BADGE_LINE_ACCENT : BADGE_LINE_GREEN;
        const char *bl = n->st == NS_OWNED
                             ? (servable ? TR(S_NAMES_BADGE_LIVE) : TR(S_NAMES_BADGE_OWNED))
                       : n->st == NS_LISTED ? TR(S_NAMES_BADGE_LISTED)
                       : n->st == NS_RESERVED ? TR(S_SCR_BADGE_RESERVED)
                       : n->st == NS_CLAIMING ? TR(S_NAMES_BADGE_CLAIMING)
                                              : TR(S_NAMES_BADGE_OFFERED);
        if (n->pending && !claiming) {          // an op is in flight — QUEUED,
            bl = TR(S_NAMES_BADGE_QUEUED);      // the badge doesn't lie "OWNED"
            bs = BADGE_FILL_ACCENT;
        }
        dk_badge(ctx, xr - 62 - dk_badge_w(bl), ry + 18, bl, bs);

        // tap the row (outside checkbox) → single-action chips
        struct nk_rect tap = nk_rect(x + 36, ry, xr - x - 36 - 120, 52);
        if (dk_click(ctx, tap) && !reserved && !claiming)
            UI.name_expanded = expanded ? -1 : i;

        if (expanded) {
            // Two gates layer here. Chain state: LISTED/OFFERED names are
            // movement-locked but stay renewable (§3.5). Queue state
            // (n->pending): a queued release/transfer/claim freezes every
            // action; a queued sell/offer freezes movement but keeps renew;
            // a queued renew only blocks stacking another renew.
            float ax = x + 42, ay = ry + 50;
            int pend = n->pending;
            int frozen = pend == OPS_PEND_RELEASE || pend == OPS_PEND_TRANSFER ||
                         pend == OPS_PEND_CLAIM || pend == OPS_PEND_OTHER;
            int unlocked = n->st == NS_OWNED && !frozen &&
                           pend != OPS_PEND_SELL && pend != OPS_PEND_OFFER;
            if (name_renewable(n) && !frozen && pend != OPS_PEND_RENEW) {
                if (dk_btn(ctx, nk_rect(ax, ay, 62, 28), F_PH14, TR(S_SCR_RENEW), BTN_ACCENT)) {
                    UI.dialog = DLG_RENEW;
                    UI.name_target = i;
                    UI.renew_days = 365 - (int)((n->expiry - M.now) / 86400);
                }
            } else {
                ui_btn_disabled(ctx, nk_rect(ax, ay, 62, 28), F_PH14, TR(S_SCR_RENEW));
            }
            // DNS / SSL — the per-name screens (9c/9d); available while the
            // name is on-chain in any state (zone edits are mesh-side)
            if (dk_btn_col(ctx, nk_rect(ax + 68, ay, 52, 28), F_PH14, TR(S_NAMES_DNS),
                           BTN_LINE_FILL, C_TEXT)) {
                UI.dns_name_sel = i;
                UI.view = V_DNS;
            }
            if (dk_btn_col(ctx, nk_rect(ax + 126, ay, 48, 28), F_PH14, TR(S_NAMES_SSL),
                           BTN_LINE_FILL, C_TEXT)) {
                UI.dns_name_sel = i;
                UI.view = V_SSL;
            }
            if (unlocked) {
                if (dk_btn_col(ctx, nk_rect(ax + 180, ay, 52, 28), F_PH14, TR(S_SCR_SELL),
                               BTN_LINE_FILL, C_TEXT)) {
                    UI.dialog = DLG_SELL;
                    UI.name_target = i;
                    UI.sell_price_len = 0;
                    UI.sell_days = 30;
                }
                if (dk_btn_col(ctx, nk_rect(ax + 238, ay, 56, 28), F_PH14, TR(S_SCR_OFFER),
                               BTN_LINE_FILL, C_TEXT)) {
                    UI.dialog = DLG_OFFER;
                    UI.name_target = i;
                    UI.send_to_len = 0;
                    UI.sell_price_len = 0;
                }
                if (dk_btn_col(ctx, nk_rect(ax + 300, ay, 72, 28), F_PH14, TR(S_SCR_TRANSFER),
                               BTN_LINE_FILL, C_TEXT)) {
                    UI.dialog = DLG_TRANSFER;
                    UI.name_target = i;
                    UI.send_to_len = 0;
                }
                if (dk_btn_col(ctx, nk_rect(ax + 378, ay, 68, 28), F_PH14, TR(S_SCR_RELEASE),
                               BTN_LINE_FILL, C_RED)) {
                    UI.dialog = DLG_RELEASE;
                    UI.name_target = i;
                }
            } else {
                // the dead buttons say it all — no status note (it overlapped
                // the Release button on narrow rows)
                ui_btn_disabled(ctx, nk_rect(ax + 180, ay, 52, 28), F_PH14, TR(S_SCR_SELL));
                ui_btn_disabled(ctx, nk_rect(ax + 238, ay, 56, 28), F_PH14, TR(S_SCR_OFFER));
                ui_btn_disabled(ctx, nk_rect(ax + 300, ay, 72, 28), F_PH14, TR(S_SCR_TRANSFER));
                ui_btn_disabled(ctx, nk_rect(ax + 378, ay, 68, 28), F_PH14, TR(S_SCR_RELEASE));
            }
        }
        ry += rh + 4;
    }
    if (M.nnames == 0) {
        struct nk_rect r = nk_rect(view.x + 50, view.y + 60, view.w - 100, 62);
        dk_rect_dashed(ctx, r, 12, C_BORDER);
        dk_text_c(ctx, F_PH18, r, C_DIM,
                  M.demo ? TR(S_NAMES_EMPTY_DEMO) : TR(S_NAMES_EMPTY));
    }
    dk_scroll_end(ctx, &UI.sc_names, view, (ry + UI.sc_names.scroll) - view.y + 4, 0);

    // sticky selection bar (9b): count · clear · est · ··· overflow · Renew N
    if (nsel) {
        struct nk_rect bar = nk_rect(area.x, area.y + area.h - bar_h, area.w, bar_h);
        dk_fill(ctx, bar, 0, C_PANEL);
        dk_hline(ctx, bar.x, bar.x + bar.w, bar.y, C_BORDER);
        snprintf(b, sizeof b, TR(S_NAMES_NSEL_FMT), nsel);
        dk_text(ctx, F_PH16, bar.x + 16, bar.y + 17, C_TEXT, b);
        struct nk_rect clr = nk_rect(bar.x + 16 + dk_w(F_PH16, b) + 12, bar.y + 19, 44, 20);
        if (dk_btn_col(ctx, clr, F_PH14, TR(S_NAMES_CLEAR), BTN_GHOST, C_GHOST)) UI.sel_mask = 0;

        snprintf(b, sizeof b, TR(S_NAMES_RENEW_N_FMT), nren);
        float rw = dk_w(F_PH16, b) + 40;
        struct nk_rect rb = nk_rect(bar.x + bar.w - 16 - rw, bar.y + 12, rw, 32);
        if (nren) {
            if (dk_btn(ctx, rb, F_PH16, b, BTN_ACCENT)) {
                UI.renew_sel = 1;               // §3.5 selective bitmap over the picks
                UI.dialog = DLG_BATCH_RENEW;
            }
        } else {
            ui_btn_disabled(ctx, rb, F_PH16, b);
        }
        // ··· overflow: Transfer N / Release N (popups.c)
        struct nk_rect mb = nk_rect(rb.x - 10 - 46, bar.y + 12, 46, 32);
        if (dk_btn_col(ctx, mb, F_PH16, "\xC2\xB7\xC2\xB7\xC2\xB7",
                       BTN_LINE_FILL, C_TEXT))
            ui_popup_open(POP_NAMES_MORE, mb);
        if (nren) {
            char eb[48];
            fmt_amount4_sp(eb, sizeof eb, est);
            snprintf(b, sizeof b, "~%s", eb);
            dk_text_r(ctx, F_SM11, mb.x - 12, bar.y + 21, C_DIM, b);
        } else if (!nrel) {
            dk_text_r(ctx, F_SM10, mb.x - 12, bar.y + 21, C_GHOST, TR(S_NAMES_NOTHING_ACT));
        }
    }
}

// ═════════════════════════════════ MARKET (3d) ══════════════════════════════
void view_market(struct nk_context *ctx, struct nk_rect area) {
    char b[96], sub[96];
    float y = area.y;
    float x = area.x + 12, xr = area.x + area.w - 12;

    // OFFERS TO ME
    if (M.noffers) {
        dk_text_sp(ctx, F_SMB9, x + 4, y + 10, C_GREEN, TR(S_MKT_OFFERS_HDR), 1);
        snprintf(b, sizeof b, "%d", M.noffers);
        dk_text(ctx, F_SM10, x + 4 + dk_w_sp(F_SMB9, TR(S_MKT_OFFERS_HDR), 1) + 8, y + 10, C_GHOST, b);
        y += 28;
        for (int i = 0; i < M.noffers; i++) {
            OfferToMe *o = &M.offers[i];
            struct nk_rect r = nk_rect(x, y, xr - x, 52);
            dk_card(ctx, r, 8, C_PANEL, C_GREEN);
            dk_text(ctx, F_SM14, x + 12, y + 8, C_TEXT, o->name);
            char p[32];
            fmt_amount_sp(p, sizeof p, o->price);
            if (o->pending)
                snprintf(sub, sizeof sub, "%s", TR(S_MKT_PAY_QUEUED));
            else
                snprintf(sub, sizeof sub, TR(S_MKT_SOLD_FMT), p);
            dk_text(ctx, F_SM10, x + 12, y + 28, C_DIM, sub);
            char amt[32];
            fmt_amount(amt, sizeof amt, o->price);
            snprintf(b, sizeof b, TR(S_MKT_PAY_FMT), amt);
            float pw = dk_w(F_PH14, b) + 26;
            struct nk_rect pb = nk_rect(xr - 10 - pw, y + 12, pw, 28);
            if (o->pending)
                ui_btn_disabled(ctx, pb, F_PH14, b);
            else if (dk_btn(ctx, pb, F_PH14, b, BTN_GREEN)) {
                UI.dialog = DLG_PAYOFFER;
                UI.offer_target = i;
            }
            char left[24];
            fmt_days_left(left, sizeof left, o->expires - M.now);
            snprintf(b, sizeof b, TR(S_MKT_LEFT_FMT), left);
            dk_text_r(ctx, F_SM11, pb.x - 10, y + 19, C_ACCENT, b);
            y += 60;
        }
        dk_hline(ctx, area.x, area.x + area.w, y + 2, C_HAIR);
        y += 4;
    }

    // LISTINGS header + search
    dk_text_sp(ctx, F_SMB9, x + 4, y + 8, C_DIM, TR(S_MKT_LISTINGS_HDR), 1);
    dk_text_r(ctx, F_SM10, xr - 4, y + 8, C_GHOST, TR(S_MKT_SORT_PRICE));
    y += 26;
    struct nk_rect sr = nk_rect(x, y, xr - x, 34);
    dk_card(ctx, sr, 8, C_INPUT, C_BORDER);
    dk_text(ctx, F_SM11, sr.x + 11, sr.y + 10, C_GHOST, "\xE2\x8C\x95");
    UI.market_q[UI.market_q_len] = 0;
    ui_edit(ctx, nk_rect(sr.x + 26, sr.y + 3, sr.w - 34, 28), UI.market_q,
            &UI.market_q_len, sizeof UI.market_q - 1, TR(S_MKT_SEARCH_PH), F_SM13, 1);
    y += 42;

    struct nk_rect view = nk_rect(area.x, y, area.w, area.y + area.h - y);
    dk_scroll_begin(ctx, &UI.sc_market, view);
    float ry = view.y + 2 - UI.sc_market.scroll;
    int shown = 0;
    for (int i = 0; i < M.nlist; i++) {
        Listing *l = &M.listings[i];
        if (UI.market_q_len && !strstr(l->name, UI.market_q)) continue;
        shown++;
        int blocked = l->reserved_by_other && !l->is_mine;
        struct nk_color namecol = blocked ? C_DIM : C_TEXT;
        dk_text(ctx, F_SM14, x + 12, ry + 8, namecol, l->name);
        // accent TLD suffix — same treatment as the My Names rows (9b)
        dk_text(ctx, F_SM14, x + 12 + dk_w(F_SM14, l->name), ry + 8,
                blocked ? C_FADE3 : C_ACCENT, APP_DOT_TLD);

        // §5: a listing priced under 2.0 has a sub-dust pay-leg — the fold
        // would honor a reserve, but the tx can't relay; never offer one
        int subdust = l->price < UI_LIST_MIN_K;

        // sub-line
        if (l->pending) {                       // our queued op speaks for the row
            const char *pl[] = { "", TR(S_SCR_RENEW), TR(S_SCR_SELL), TR(S_SCR_OFFER),
                                 TR(S_SCR_TRANSFER), TR(S_SCR_RELEASE), TR(S_SCR_CLAIM),
                                 "" };
            const char *what = l->pending > 0 && l->pending < 7 ? pl[l->pending]
                             : l->reserved_by_me ? TR(S_MKT_WHAT_SETTLE)  // OPS_PEND_OTHER:
                             : l->is_mine        ? TR(S_MKT_RECLAIM)      // a buy-side leg
                                                 : TR(S_MKT_WHAT_RESERVE);
            snprintf(sub, sizeof sub, TR(S_SCR_QUEUED_FMT), what);
        } else if (l->is_mine) {
            if (l->reserved_by_me)
                snprintf(sub, sizeof sub, "%s", TR(S_MKT_RECLAIMING_SUB));
            else if (l->reserved_by_other)
                snprintf(sub, sizeof sub, "%s", TR(S_MKT_YOURS_RESERVED_SUB));
            else if (l->window_end <= M.now)
                snprintf(sub, sizeof sub, "%s", TR(S_MKT_YOURS_CLOSED_SUB));
            else {
                char left[24];
                fmt_days_left(left, sizeof left, l->window_end - M.now);
                if (subdust)
                    snprintf(sub, sizeof sub, TR(S_MKT_YOURS_SUBDUST_FMT), left);
                else
                    snprintf(sub, sizeof sub, TR(S_MKT_YOURS_LEFT_FMT), left);
            }
        } else if (blocked) {
            char left[24];
            fmt_days_left(left, sizeof left, l->reserve_end - M.now);
            snprintf(sub, sizeof sub, TR(S_MKT_RESERVED_OTHER_FMT), left);
        } else if (l->reserved_by_me) {
            char left[24];
            fmt_days_left(left, sizeof left, l->reserve_end - M.now);
            snprintf(sub, sizeof sub, TR(S_MKT_RESERVED_YOU_FMT), left);
        } else if (l->window_end <= M.now) {
            snprintf(sub, sizeof sub, "%s", TR(S_MKT_WINDOW_CLOSED));
        } else if (subdust) {
            snprintf(sub, sizeof sub, "%s", TR(S_MKT_SUBDUST_SUB));
        } else {
            int64_t s = l->window_end - M.now;
            int64_t d = s / 86400, hrs = (s % 86400) / 3600;
            if (d > 0 && d < 3 && hrs > 0)
                snprintf(sub, sizeof sub, TR(S_MKT_DH_LEFT_FMT), (long long)d, (long long)hrs);
            else {
                char left[24];
                fmt_days_left(left, sizeof left, s);
                snprintf(sub, sizeof sub, TR(S_MKT_LEFT_FMT), left);
            }
        }
        dk_text(ctx, F_SM10, x + 12, ry + 28, C_GHOST, sub);

        char p[32];
        fmt_amount(p, sizeof p, l->price);
        snprintf(b, sizeof b, "%s " GLY_P, p);
        if (l->is_mine) {                       // our own listing — reclaim = self-buy (§3.7)
            if (l->reserved_by_me) {            // self-reserved → settle to finish the reclaim
                struct nk_rect sb = nk_rect(xr - 10 - 66, ry + 11, 66, 28);
                if (l->pending)
                    ui_btn_disabled(ctx, sb, F_PH14, TR(S_MKT_SETTLE));
                else if (dk_btn(ctx, sb, F_PH14, TR(S_MKT_SETTLE), BTN_GREEN)) {
                    UI.dialog = DLG_SETTLE;
                    UI.listing_target = i;
                }
                dk_text_r(ctx, F_SM14, sb.x - 10, ry + 16, C_TEXT, b);
            } else if (l->reserved_by_other) {  // a buyer holds it — can't reclaim now
                float bw = dk_badge_w(TR(S_MKT_BADGE_YOURS));
                dk_badge(ctx, xr - 10 - bw, ry + 17, TR(S_MKT_BADGE_YOURS), BADGE_LINE_ACCENT);
                dk_text_r(ctx, F_SM14, xr - 18 - bw, ry + 16, C_DIM, b);
            } else if (l->window_end <= M.now || l->pending || subdust) {
                struct nk_rect bb = nk_rect(xr - 10 - 74, ry + 11, 74, 28);
                ui_btn_disabled(ctx, bb, F_PH14, TR(S_MKT_RECLAIM));
                dk_text_r(ctx, F_SM14, bb.x - 10, ry + 16, C_GHOST, b);
            } else {                            // open → reclaim it (self-RESERVE, then Settle)
                struct nk_rect bb = nk_rect(xr - 10 - 74, ry + 11, 74, 28);
                if (dk_btn_col(ctx, bb, F_PH14, TR(S_MKT_RECLAIM), BTN_LINE_FILL, C_ACCENT)) {
                    UI.dialog = DLG_BID;
                    UI.listing_target = i;
                }
                dk_text_r(ctx, F_SM14, bb.x - 10, ry + 16, C_TEXT, b);
            }
        } else if (blocked) {
            float bw = dk_badge_w(TR(S_SCR_BADGE_RESERVED));
            dk_badge(ctx, xr - 10 - bw, ry + 17, TR(S_SCR_BADGE_RESERVED), BADGE_LINE_ACCENT);
            dk_text_r(ctx, F_SM14, xr - 18 - bw, ry + 16, C_DIM, b);
            struct nk_rect row = nk_rect(x, ry, xr - x, 50);
            if (dk_click(ctx, row)) {
                UI.dialog = DLG_BLOCKED;
                UI.listing_target = i;
            }
        } else if (l->reserved_by_me) {
            struct nk_rect sb = nk_rect(xr - 10 - 66, ry + 11, 66, 28);
            if (l->pending)
                ui_btn_disabled(ctx, sb, F_PH14, TR(S_MKT_SETTLE));
            else if (dk_btn(ctx, sb, F_PH14, TR(S_MKT_SETTLE), BTN_GREEN)) {
                UI.dialog = DLG_SETTLE;
                UI.listing_target = i;
            }
            dk_text_r(ctx, F_SM14, sb.x - 10, ry + 16, C_TEXT, b);
        } else if (l->window_end <= M.now || l->pending || subdust) {
            struct nk_rect bb = nk_rect(xr - 10 - 56, ry + 11, 56, 28);
            ui_btn_disabled(ctx, bb, F_PH14, TR(S_MKT_BID));
            dk_text_r(ctx, F_SM14, bb.x - 10, ry + 16, C_GHOST, b);
        } else {
            struct nk_rect bb = nk_rect(xr - 10 - 56, ry + 11, 56, 28);
            if (dk_btn_col(ctx, bb, F_PH14, TR(S_MKT_BID), BTN_LINE_FILL, C_TEXT)) {
                UI.dialog = DLG_BID;
                UI.listing_target = i;
            }
            dk_text_r(ctx, F_SM14, bb.x - 10, ry + 16, C_TEXT, b);
        }
        dk_hline(ctx, x + 4, xr - 4, ry + 49, C_HAIR);
        ry += 50;
    }
    if (shown == 0) {                           // honest empty (no listings, or no search hit)
        const char *msg = UI.market_q_len ? TR(S_MKT_EMPTY_SEARCH)
                        : (!M.demo && !M.synced ? TR(S_MKT_EMPTY_SYNCING)
                                                : TR(S_MKT_EMPTY));
        dk_text_c(ctx, F_PH16, nk_rect(view.x, ry + 24, view.w, 30), C_DIM, msg);
        ry += 70;
    }
    dk_scroll_end(ctx, &UI.sc_market, view, (ry + UI.sc_market.scroll) - view.y + 8, 0);
}

// ═════════════════════════════════ RECEIVE (6a) ═════════════════════════════
void view_receive(struct nk_context *ctx, struct nk_rect area) {
    ui_screen_header(ctx, area, TR(S_RECV_TITLE));
    float cx = area.x + area.w / 2;
    float y = area.y + 64;

    if (!M.has_wallet) {
        // a denied keychain read is NOT "no wallet" — the key almost certainly
        // still exists (wallet.c refuses to mint a replacement); say what to fix
        int den = WLT.denied;
        struct nk_rect r = nk_rect(cx - 210, y + 90, 420, 80);
        dk_rect_dashed(ctx, r, 12, den ? C_TINT_RED_BR : C_BORDER);
        dk_text_c(ctx, F_PH18, nk_rect(r.x, r.y + 8, r.w, 30), C_DIM,
                  TR(den ? S_SCR_KEY_DENIED : S_SCR_NO_WALLET));
        dk_text_c(ctx, F_PH12, nk_rect(r.x, r.y + 42, r.w, 20), den ? C_RED : C_GHOST,
                  TR(den ? S_SCR_KEY_DENIED_SUB : S_SCR_NO_WALLET_SUB));
        return;
    }

    dk_text_c(ctx, F_PH16, nk_rect(area.x, y, area.w, 22), C_DIM,
              M.demo ? TR(S_RECV_SCAN_DEMO)
                     : TR(S_RECV_SCAN));
    y += 36;

    // the real QR of this wallet's address (qr.c — byte mode, ECC L). Encoded
    // once and cached; the address never changes within a run (a phrase
    // restore swaps it, so the texture rebuilds on address change).
    //
    // The grid draws as ONE nearest-sampled texture (a texel per module),
    // not per-module rects: sokol_nuklear converts every filled rect with
    // shape_AA forced on, so abutting rects feather a blended seam at their
    // shared edge no matter how the coordinates are snapped — texel
    // boundaries inside a single quad cannot feather. The cream card
    // supplies the spec's 4-module quiet zone around the quad.
    static char qaddr[64];
    static int qn;
    static struct nk_image qimg;               // the module grid, one texel per module
    static snk_image_t qsi; static sg_image qtex; static sg_view qview;
    static sg_sampler qsmp;
    if (strcmp(qaddr, M.address) != 0) {
        snprintf(qaddr, sizeof qaddr, "%s", M.address);
        unsigned char qmod[QR_MAX_SIZE * QR_MAX_SIZE];
        if (qr_encode(qaddr, qmod, &qn)) {
            static uint32_t px[QR_MAX_SIZE * QR_MAX_SIZE];
            const struct nk_color mc = C_BG, lc = C_TEXT;    // dark module / light card
            uint32_t dark  = (uint32_t)mc.r | ((uint32_t)mc.g << 8) | ((uint32_t)mc.b << 16) | 0xFF000000u;
            uint32_t light = (uint32_t)lc.r | ((uint32_t)lc.g << 8) | ((uint32_t)lc.b << 16) | 0xFF000000u;
            for (int i = 0; i < qn * qn; i++) px[i] = qmod[i] ? dark : light;
            if (qtex.id) { snk_destroy_image(qsi); sg_destroy_view(qview); sg_destroy_image(qtex); }
            if (qsmp.id == 0)
                qsmp = sg_make_sampler(&(sg_sampler_desc){
                    .min_filter = SG_FILTER_NEAREST, .mag_filter = SG_FILTER_NEAREST,
                    .label = "qr-smp",
                });
            qtex = sg_make_image(&(sg_image_desc){
                .width = qn, .height = qn,
                .pixel_format = SG_PIXELFORMAT_RGBA8,
                .data.mip_levels[0] = { .ptr = px, .size = (size_t)qn * (size_t)qn * 4 },
                .label = "qr",
            });
            qview = sg_make_view(&(sg_view_desc){ .texture.image = qtex });
            qsi = snk_make_image(&(snk_image_desc_t){ .texture_view = qview, .sampler = qsmp });
            qimg = nk_image_handle(snk_nkhandle(qsi));
        } else qn = 0;
    }
    if (qn) {
        // module ≈ 6 logical px, snapped to whole device pixels so the quad
        // spans exactly qn·ud device px — one texel maps to ud whole pixels
        float S = app_px_scale();
        int   ud = (int)(6.0f * S + 0.5f);
        if (ud < 2) ud = 2;
        float u = ud / S;
        float quiet = 4 * u, side = qn * u + 2 * quiet;
        float cardx = (int)((cx - side / 2) * S + 0.5f) / S;   // origin on a device pixel
        float cardy = (int)(y * S + 0.5f) / S;
        struct nk_rect card = nk_rect(cardx, cardy, side, side);
        dk_fill(ctx, card, 14, C_TEXT);
        struct nk_rect qrect = nk_rect(cardx + quiet, cardy + quiet, qn * u, qn * u);
        nk_draw_image(dk_cv(ctx), qrect, &qimg, nk_rgba(255, 255, 255, 255));
        y = card.y + card.h + 26;
    } else {
        y += 18;
    }

    float bw = 380 < area.w - 48 ? 380 : area.w - 48;
    float bx = cx - bw / 2;
    dk_text_c(ctx, F_SM9, nk_rect(area.x, y, area.w, 14), C_GHOST, TR(S_RECV_ADDR_HDR));
    y += 22;
    float ah = dk_wrap(NULL, F_SM13, 0, 0, bw - 28, C_TEXT, M.address, 1.4f);
    struct nk_rect ab = nk_rect(bx, y, bw, ah + 22);
    dk_card(ctx, ab, 10, C_PANEL, C_BORDER);
    dk_wrap(ctx, F_SM13, bx + 14, y + 11, bw - 28, C_TEXT, M.address, 1.4f);
    y += ab.h + 12;

    if (dk_btn(ctx, nk_rect(bx, y, bw, 38), F_PH16, TR(S_RECV_COPY), BTN_ACCENT))
        sapp_set_clipboard_string(M.address);
    y += 52;
    dk_text_c(ctx, F_PH12, nk_rect(area.x, y, area.w, 18), C_GHOST,
              TR(S_RECV_FOOT));
    if (!M.demo && WLT.ok) {                        // key-storage honesty
        y += 22;
        dk_text_c(ctx, F_SM9, nk_rect(area.x, y, area.w, 14), C_GHOST,
                  TR(S_RECV_KEYNOTE));
    }
}

// ═════════════════════════════════ SEND (6b) ════════════════════════════════
void view_send(struct nk_context *ctx, struct nk_rect area) {
    char b[96];
    ui_screen_header(ctx, area, TR(S_SEND_TITLE));
    // balance readout on the title line
    fmt_amount_p(b, sizeof b, M.balance);
    dk_text_r(ctx, F_SM13, area.x + area.w - 16, area.y + 16, C_TEXT, b);
    dk_text_r(ctx, F_SM11, area.x + area.w - 20 - dk_w(F_SM13, b), area.y + 18, C_GHOST, TR(S_SEND_BALANCE));

    float x = area.x + 20, xr = area.x + area.w - 20;
    float y = area.y + 68;

    if (!M.has_wallet) {
        struct nk_rect r = nk_rect(area.x + area.w / 2 - 180, y + 80, 360, 80);
        dk_rect_dashed(ctx, r, 12, C_BORDER);
        dk_text_c(ctx, F_PH18, nk_rect(r.x, r.y + 8, r.w, 30), C_DIM, TR(S_SCR_NO_WALLET));
        dk_text_c(ctx, F_PH12, nk_rect(r.x, r.y + 42, r.w, 20), C_GHOST,
                  TR(S_SCR_NO_WALLET_SUB));
        return;
    }

    // to — address or name. A real base58check decode against the coin's
    // version byte; live names resolve through the projection itself (the
    // fold's owner column), demo names resolve to a fixture address.
    UI.send_to[UI.send_to_len] = 0;
    int addr_ok = wallet_addr_valid(UI.send_to);
    int name_syn = UI.send_to_len > 0 &&
                   sm_name_valid(UI.send_to, (size_t)UI.send_to_len);
    uint8_t to160[20] = { 0 };
    int name_res = 0;               // live: 1 resolved · -1 non-P2PKH owner · 0 unknown
    char res_addr[64] = "";
    if (addr_ok) {
        wallet_addr_decode(UI.send_to, to160);
    } else if (name_syn && !M.demo) {
        name_res = engine_name_lookup(UI.send_to, to160, NULL);
        if (name_res == 1) wallet_h160_addr(to160, res_addr, sizeof res_addr);
    }
    int rcpt_ok = addr_ok || (M.demo && name_syn) || name_res == 1;
    dk_text(ctx, F_PH14, x, y, C_DIM, TR(S_SEND_TO_LABEL));
    y += 22;
    struct nk_rect tr = nk_rect(x, y, xr - x, 42);
    dk_card(ctx, tr, 10, C_INPUT,
            UI.send_to_len && !rcpt_ok && !name_syn ? C_RED : C_BORDER);
    struct nk_rect paste = nk_rect(tr.x + tr.w - 52, tr.y + 10, 44, 22);
    ui_edit(ctx, nk_rect(tr.x + 6, tr.y + 6, tr.w - 64, 30), UI.send_to,
            &UI.send_to_len, sizeof UI.send_to - 1, TR(S_SEND_TO_PH), F_SM13, 1);
    if (dk_btn_col(ctx, paste, F_PH14, TR(S_SEND_PASTE), BTN_GHOST, C_DIM)) {
        const char *cp = sapp_get_clipboard_string();
        if (cp && cp[0]) {
            snprintf(UI.send_to, sizeof UI.send_to, "%.*s", (int)sizeof UI.send_to - 1, cp);
            UI.send_to_len = (int)strlen(UI.send_to);
        }
    }
    y += 48;
    if (addr_ok) {
        dk_text(ctx, F_SM10, x, y, C_GREEN, TR(S_SEND_VALID_ADDR));
        y += 20;
    } else if (name_syn && M.demo) {                // fixture resolve
        dk_text(ctx, F_SM10, x, y, C_GREEN, TR(S_SEND_NAME_DEMO));
        y += 20;
    } else if (name_syn && !M.demo) {
        if (name_res == 1) {
            char sr[32], rb[64];
            size_t rl = strlen(res_addr);
            if (rl > 13) snprintf(sr, sizeof sr, "%.6s…%s", res_addr, res_addr + rl - 5);
            else snprintf(sr, sizeof sr, "%s", res_addr);
            snprintf(rb, sizeof rb, TR(S_SEND_NAME_RES_FMT), sr);
            dk_text(ctx, F_SM10, x, y, C_GREEN, rb);
        } else if (name_res == -1) {
            dk_text(ctx, F_SM10, x, y, C_RED, TR(S_SEND_ERR_NOTPLAIN));
        } else {
            dk_text(ctx, F_SM10, x, y, C_RED, TR(S_SEND_ERR_NONAME));
        }
        y += 20;
    } else if (UI.send_to_len) {
        char eb[64];
        snprintf(eb, sizeof eb, TR(S_SEND_ERR_ADDR_FMT), wallet_coin());
        dk_text(ctx, F_SM10, x, y, C_RED, eb);
        y += 20;
    } else {
        y += 4;
    }

    // amount — strict parse; the wallet refuses sub-dust sends (0.01 floor)
    int64_t amt = 0;
    UI.send_amt[UI.send_amt_len] = 0;
    int amt_num = fmt_parse_amount(UI.send_amt, &amt) && amt > 0;
    int amt_short = amt_num && amt + UI_FEE_K > M.balance;
    int amt_dust = amt_num && amt < 1000000;
    int amt_ok = amt_num && !amt_short && !amt_dust;
    dk_text(ctx, F_PH14, x, y, C_DIM, TR(S_SEND_AMOUNT));
    char avail[64], am[48];
    fmt_amount(am, sizeof am, M.balance);
    snprintf(avail, sizeof avail, TR(S_SEND_AVAIL_FMT), am);
    dk_text_r(ctx, F_SM10, xr, y + 3, amt_short ? C_RED : C_GHOST, avail);
    y += 22;
    struct nk_rect ar = nk_rect(x, y, xr - x, 56);
    dk_card(ctx, ar, 10, C_INPUT,
            UI.send_amt_len && !amt_num ? C_RED : C_BORDER);
    dk_text(ctx, F_SM16, ar.x + 16, ar.y + 18, C_GHOST, GLY_P);
    struct nk_rect mx = nk_rect(ar.x + ar.w - 56, ar.y + 16, 44, 24);
    ui_edit(ctx, nk_rect(ar.x + 38, ar.y + 9, ar.w - 104, 38), UI.send_amt,
            &UI.send_amt_len, sizeof UI.send_amt - 1, "0.00", F_SM26, 1);
    dk_line_rect(ctx, mx, 6, C_ACCENT);
    dk_text_c(ctx, F_SM11, mx, C_ACCENT, TR(S_SEND_MAX));
    if (dk_hot(ctx, mx)) sapp_set_mouse_cursor(SAPP_MOUSECURSOR_POINTING_HAND);
    if (dk_click(ctx, mx)) {
        int64_t maxv = M.balance - UI_FEE_K;
        if (maxv < 0) maxv = 0;
        fmt_amount(UI.send_amt, sizeof UI.send_amt, maxv);
        UI.send_amt_len = (int)strlen(UI.send_amt);
    }
    y += 74;

    // fee + total
    dk_hline(ctx, x, xr, y, C_HAIR);
    y += 14;
    char fb[56];
    fmt_amount_sp(b, sizeof b, UI_FEE_K);
    snprintf(fb, sizeof fb, "+%s", b);
    ui_kv_row(ctx, x, xr, y, TR(S_SEND_FEE), fb, C_DIM, C_DIM);
    y += 22;
    dk_hline(ctx, x, xr, y, C_HAIR);
    y += 10;
    dk_text(ctx, F_SM13, x, y, C_TEXT, TR(S_SEND_TOTAL));
    fmt_amount_sp(b, sizeof b, amt_num ? amt + UI_FEE_K : 0);
    dk_text_r(ctx, F_SM14, xr, y - 1, C_ACCENT, b);

    // send — both planes validate the same way; live hands the tx to ops.h
    // (wallet build → sign → self-check → broadcast on a worker thread)
    float by = area.y + area.h - 96;
    const char *gate = M.demo ? NULL : ops_gate();
    const char *why = NULL;
    if (UI.send_amt_len && !amt_num) why = TR(S_SEND_ERR_AMT);
    else if (amt_dust) why = TR(S_SEND_ERR_DUST);
    else if (amt_short) {
        static char sb[80];
        char need[48];
        fmt_amount4_sp(need, sizeof need, amt + UI_FEE_K - M.balance);
        snprintf(sb, sizeof sb, TR(S_SEND_ERR_SHORT_FMT), need);
        why = sb;
    }
    else if (gate && rcpt_ok && amt_ok) why = gate;
    int can = rcpt_ok && amt_ok && !gate;
    if (can) {
        if (dk_btn(ctx, nk_rect(x, by, xr - x, 44), F_PH18, TR(S_SEND_SEND), BTN_ACCENT)) {
            if (!M.demo) {
                // a send that can't leave a ≥dust change is a sweep: build it
                // changeless so "max" (balance − fee) spends every last koinu
                // instead of failing on the mandatory dust change buffer.
                int sweep = amt + UI_FEE_K + UI_DUST_K > M.balance;
                ops_send(to160, amt, sweep);   // outcome lands on the status pill
                UI.send_amt_len = 0;
            } else {
                M.balance -= amt + UI_FEE_K;
                UI.send_amt_len = 0;
                UI.send_flash = 240;
            }
        }
    } else {
        ui_btn_disabled(ctx, nk_rect(x, by, xr - x, 44), F_PH18, TR(S_SEND_SEND));
    }
    if (why) {
        dk_text_c(ctx, F_SM10, nk_rect(area.x, by - 26, area.w, 16), C_RED, why);
    } else if (UI.send_flash > 0) {
        UI.send_flash--;
        dk_text_c(ctx, F_SM11, nk_rect(area.x, by - 26, area.w, 16), C_GREEN,
                  TR(S_SEND_SENT_FLASH));
    }
    dk_text_c(ctx, F_PH12, nk_rect(area.x, by + 52, area.w, 18), C_GHOST,
              M.demo ? TR(S_SEND_FOOT_DEMO)
                     : TR(S_SEND_FOOT_LIVE));
}

// ═════════════════════════════════ SETTINGS ═════════════════════════════════
// install-state probe, cached ~5 s (the shellouts are not free)
static InstallState g_set_inst;
static int64_t g_set_inst_at;
static const InstallState *settings_inst(void) {
    if (M.now - g_set_inst_at >= 5) { sysinstall_probe(&g_set_inst); g_set_inst_at = M.now; }
    return &g_set_inst;
}
void view_settings(struct nk_context *ctx, struct nk_rect area) {
    char b[128];
    ui_screen_header(ctx, area, TR(S_SET_TITLE));
    struct nk_rect sview = nk_rect(area.x, area.y + 56, area.w, area.h - 56);
    dk_scroll_begin(ctx, &UI.sc_set, sview);
    float x = area.x + 20, y = sview.y + 10 - UI.sc_set.scroll;
    // ── browser access (9h's system pieces, revisitable here) ────────────────
    if (!M.demo) {
        dk_text_sp(ctx, F_SM9, x, y, C_GHOST, TR(S_SET_BROWSER_HDR), 1);
        y += 20;
        const InstallState *is = settings_inst();
        ui_kv_row(ctx, x, area.x + area.w - 20, y, TR(S_SET_ROOTCERT),
                  is->ca_trusted ? TR(S_SET_TRUSTED) : TR(S_SET_NOT_INSTALLED), C_GHOST,
                  is->ca_trusted ? C_DIM : C_GHOST);
        y += 22;
        ui_kv_row(ctx, x, area.x + area.w - 20, y, "/etc/resolver/" APP_TLD,
                  is->resolver_file ? TR(S_SET_PRESENT) : TR(S_SET_MISSING), C_GHOST,
                  is->resolver_file ? C_DIM : C_GHOST);
        y += 22;
        ui_kv_row(ctx, x, area.x + area.w - 20, y,
                  TR(S_SET_PORTREDIR),
                  is->pf_anchor ? TR(S_SET_CONFIGURED) : TR(S_SET_NOT_CONFIGURED), C_GHOST,
                  is->pf_anchor ? C_DIM : C_GHOST);
        y += 30;
        int fully = is->ca_trusted && is->resolver_file && is->pf_anchor;
        struct nk_rect ib = nk_rect(x, y, 190, 30);
        if (UI.web_busy > 0) {
            ui_btn_disabled(ctx, ib, F_PH14, UI.web_note);
            UI.web_busy--;
        } else if (!fully) {
            if (dk_btn(ctx, ib, F_PH14, TR(S_SET_ENABLE_WEB), BTN_ACCENT)) {
                int ok = sysinstall_install();
                sysinstall_consent_mark();
                snprintf(UI.web_note, sizeof UI.web_note,
                         "%s", ok ? TR(S_SET_ENABLED_OK) : TR(S_SET_INSTALL_INC));
                UI.web_busy = 180;
                g_set_inst_at = 0;                  // force a re-probe
            }
        } else {
            if (dk_btn_col(ctx, ib, F_PH14, TR(S_SET_UNINSTALL_WEB), BTN_LINE, C_RED)) {
                int ok = sysinstall_uninstall();
                snprintf(UI.web_note, sizeof UI.web_note,
                         "%s", ok ? TR(S_SET_REMOVED_OK) : TR(S_SET_UNINSTALL_INC));
                UI.web_busy = 180;
                g_set_inst_at = 0;
            }
        }
        y += 40;
    }

    // ── startup ──────────────────────────────────────────────────────────────
    if (!M.demo) {
        y += 16;
        dk_hline(ctx, x, area.x + area.w - 20, y, C_HAIR);
        y += 12;
        dk_text_sp(ctx, F_SM9, x, y, C_GHOST, TR(S_SET_STARTUP_HDR), 1);
        y += 20;
        int li = sysinstall_loginitem_state();
        dk_text(ctx, F_PH14, x, y + 2, C_TEXT, TR(S_SET_LOGIN));
        dk_text(ctx, F_SM10, x, y + 21, C_GHOST, TR(S_SET_LOGIN_SUB));
        if (ui_toggle(ctx, nk_rect(area.x + area.w - 20 - 30, y + 6, 30, 16), li))
            sysinstall_loginitem_set(!li);
        y += 46;
    }

    // ── wallet recovery phrase (BIP39) ───────────────────────────────────────
    if (!M.demo && WLT.ok) {
        y += 16;
        dk_hline(ctx, x, area.x + area.w - 20, y, C_HAIR);
        y += 12;
        dk_text_sp(ctx, F_SM9, x, y, C_GHOST, TR(S_SET_PHRASE_HDR), 1);
        y += 20;
        ui_kv_row(ctx, x, area.x + area.w - 20, y, TR(S_SET_BACKUP),
                  TR(S_SET_PHRASE_12), C_GHOST, C_DIM);
        y += 28;
        if (dk_btn(ctx, nk_rect(x, y, 200, 30), F_PH14,
                   TR(S_SET_REVEAL), BTN_LINE))
            UI.dialog = DLG_REVEAL_PHRASE;
        if (dk_btn(ctx, nk_rect(x + 210, y, 150, 30), F_PH14, TR(S_SET_RESTORE), BTN_LINE)) {
            UI.restore_buf[0] = 0; UI.restore_len = 0;
            UI.restore_msg[0] = 0; UI.restore_done = 0;
            UI.dialog = DLG_RESTORE_PHRASE;
        }
        y += 40;
    }

    // ── data location ────────────────────────────────────────────────────────
    if (!M.demo) {
        static char data_note[224];              // "restart to use it" note, set on change
        char dir[600]; platform_data_dir(dir, sizeof dir);
        y += 16;
        dk_hline(ctx, x, area.x + area.w - 20, y, C_HAIR);
        y += 12;
        dk_text_sp(ctx, F_SM9, x, y, C_GHOST, TR(S_SET_DATA_HDR), 1);
        y += 18;
        float ph = dk_wrap(NULL, F_SM10, 0, 0, area.w - 40, C_DIM, dir, 1.3f);
        dk_wrap(ctx, F_SM10, x, y, area.w - 40, C_DIM, dir, 1.3f);
        y += ph + 8;
        if (dk_btn(ctx, nk_rect(x, y, 150, 30), F_PH14, TR(S_SET_DATA_OPEN), BTN_LINE))
            platform_reveal_file(dir);
        if (dk_btn(ctx, nk_rect(x + 160, y, 190, 30), F_PH14, TR(S_SET_DATA_CHANGE), BTN_LINE)) {
            char chosen[600];
            if (platform_choose_directory(chosen, sizeof chosen)) {
                platform_config_set("data_dir", chosen);
                snprintf(data_note, sizeof data_note, TR(S_SET_DATA_MOVED_FMT), chosen);
            }
        }
        y += 38;
        if (data_note[0]) {
            dk_wrap(ctx, F_SM10, x, y, area.w - 40, C_ACCENT, data_note, 1.35f);
            y += 30;
        }
    }
    y += 16;
    dk_scroll_end(ctx, &UI.sc_set, sview, (y + UI.sc_set.scroll) - sview.y, 0);
}
