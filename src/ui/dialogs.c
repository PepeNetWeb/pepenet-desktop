// dialogs.c — the modal cards. Every rule the protocol enforces gets said out
// loud here BEFORE money moves: the 365-day renew cap (rent past it burns for
// nothing), the non-refundable 1% bid, the blocked double-reserve.
// The validation spine: each dialog computes its blocker (`why`) BEFORE its
// height. why == NULL → actionable; why == "" → confirm dead, the reason is
// already on screen; why == "…" → confirm dead + red line above the buttons
// (dialogs add why_h() to their height for it). Checks mirror the consensus
// fold (protocol state.c/market.c/lease.c) and wallet's client guards.
//
// Commits are dual-plane: demo mutates the fixtures; live submits the REAL
// op through ops.h (wallet build → sign → self-check → broadcast on a
// worker) and lets the projection deliver the outcome — the dialog never
// pretends a tx confirmed. Live renew/release/transfer ride §3.5's SELECTIVE
// bitmap (one tx renews/releases/gifts exactly the chosen names; "renew all
// names" keeps the bare whole-set water-fill), and §3.7 SELL_TO makes a
// directed offer with the fixed 2 h window.
#include "ui.h"
#include "../wallet.h"
#include "../bip39.h"
#include "../ops.h"
#include "../engine.h"
#include "../dnsnet.h"
#include "../webproxy.h"
#include "../dirscan.h"
#include "../sysinstall.h"
#include "dns_wire.h"

#include "../../vendor/sokol/sokol_app.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Every action dialog exits through here. Re-reading the pending flags on close
// flips the just-submitted row's button to disabled on this frame — the queue is
// live the instant ops_* returned, so we needn't wait for the op to fold. On a
// cancel it's a harmless no-op (nothing was queued).
static void close_dlg(void) { UI.dialog = DLG_NONE; model_refresh_pending(); }

static struct nk_rect dlg_begin(struct nk_context *ctx, struct nk_rect screen,
                                float w, float h, struct nk_color border) {
    dk_scrim(ctx, screen);
    float x = screen.x + (screen.w - w) / 2;
    float y = screen.y + (screen.h - h) / 2;
    if (y < 50) y = 50;
    struct nk_rect r = nk_rect(x, y, w, h);
    dk_card(ctx, r, 12, C_PANEL, border);
    return r;
}

// title: hand voice + mono name (money-true) on one baseline
static void dlg_title(struct nk_context *ctx, float x, float y,
                      const char *hand, const char *mono, struct nk_color handc,
                      struct nk_color monoc) {
    dk_text(ctx, F_PH22, x, y, handc, hand);
    if (mono) dk_text(ctx, F_SM16, x + dk_w(F_PH22, hand) + 8, y + 5, monoc, mono);
}

// returns 1 = left/cancel, 2 = right/ok
static int dlg_pair(struct nk_context *ctx, float x, float y, float w,
                    const char *cancel, const char *ok, BtnStyle okst, float flex) {
    float cw = (w - 8) / (1.0f + flex);
    float ow = w - 8 - cw;
    int r = 0;
    if (dk_btn_col(ctx, nk_rect(x, y, cw, 38), F_PH16, cancel, BTN_LINE_FILL, C_DIM)) r = 1;
    if (dk_btn(ctx, nk_rect(x + cw + 8, y, ow, 38), F_PH16, ok, okst)) r = 2;
    return r;
}

// gated variant: why != NULL kills the confirm side (cancel stays live)
static int dlg_pair_gated(struct nk_context *ctx, float x, float y, float w,
                          const char *cancel, const char *ok, BtnStyle okst,
                          float flex, const char *why) {
    if (!why) return dlg_pair(ctx, x, y, w, cancel, ok, okst, flex);
    float cw = (w - 8) / (1.0f + flex);
    int r = dk_btn_col(ctx, nk_rect(x, y, cw, 38), F_PH16, cancel,
                       BTN_LINE_FILL, C_DIM) ? 1 : 0;
    ui_btn_disabled(ctx, nk_rect(x + cw + 8, y, w - 8 - cw, 38), F_PH16, ok);
    return r;
}

static char why_buf[96];

static const char *why_funds(int64_t total) {          // NULL = affordable
    if (M.balance >= total) return NULL;
    char need[48];
    fmt_amount4_sp(need, sizeof need, total - M.balance);
    snprintf(why_buf, sizeof why_buf, TR(S_DLG_WHY_SHORT_FMT), need);
    return why_buf;
}
// the standard money gate: live must have a signer and queue room, and
// either plane must afford the total
static const char *why_pay(int64_t total) {
    if (!M.demo) {
        const char *gate = ops_gate();
        if (gate) return gate;
    }
    return why_funds(total);
}

// the queue's per-name matrix, mirrored by the row chips: a queued release/
// transfer/claim freezes the name; a queued sell/offer still allows renew
static const char *why_queued(const MyName *n, int renewing) {
    if (!n->pending) return NULL;
    if (renewing && (n->pending == OPS_PEND_SELL || n->pending == OPS_PEND_OFFER))
        return NULL;
    return TR(S_DLG_WHY_QUEUED);
}

// §3.4 exact rent: rate is koinu per name-quantum (28 d), so T name·days cost
// ⌈T·rate/28⌉ — the fold rounds DOWN days-per-koinu, so round the koinu UP
static int64_t rent_for_days(int64_t T) {
    return (T * (int64_t)M.rate + 27) / 28;
}
// live headroom of one name against now+MAX_LEASE, whole days
static int64_t head_days(int64_t expiry) {
    int64_t rem = expiry - M.now;
    if (rem < 0) rem = 0;
    int64_t hd = (365 * 86400 - rem) / 86400;
    return hd < 0 ? 0 : hd;
}
static float why_h(const char *why) { return why && why[0] ? 16.0f : 0.0f; }
static void why_line(struct nk_context *ctx, float x, float buttons_y,
                     const char *why) {
    if (why && why[0]) dk_text(ctx, F_SM10, x, buttons_y - 16, C_RED, why);
}

// one reserve-deposit leg (mirrors market.c deposit_leg): 0.5% of price, ≥1;
// the full deposit is two legs — 0.5% burned + 0.5% to the seller
static int64_t dep_leg(int64_t price) {
    int64_t l = price * 50 / 10000;
    return l < 1 ? 1 : l;
}

static void fee_total(struct nk_context *ctx, float x, float xr, float *y,
                      int64_t fee, int64_t total, struct nk_color totalc) {
    char b[48];
    fmt_amount_sp(b, sizeof b, fee);
    char fb[56];
    snprintf(fb, sizeof fb, "+%s", b);
    ui_kv_row(ctx, x, xr, *y, TR(S_DLG_FEE), fb, C_GHOST, C_DIM);
    *y += 18;
    dk_hline(ctx, x, xr, *y + 2, C_BORDER);
    *y += 9;
    dk_text(ctx, F_SM13, x, *y, C_TEXT, TR(S_DLG_TOTAL));
    fmt_amount4_sp(b, sizeof b, total);
    dk_text_r(ctx, F_SM14, xr, *y - 1, totalc, b);
    *y += 24;
}

static void names_remove(int idx) {
    for (int i = idx; i < M.nnames - 1; i++) M.names[i] = M.names[i + 1];
    if (M.nnames > 0) M.nnames--;
    UI.sel_mask = 0;
}

static int64_t days_remaining(int64_t expiry) {
    int64_t d = (expiry - M.now) / 86400;
    return d < 0 ? 0 : d;
}
static void d_renew(struct nk_context *ctx, struct nk_rect screen) {
    MyName *n = &M.names[UI.name_target];
    int cap = 365 - (int)days_remaining(n->expiry);   // headroom to now+MAX_LEASE
    if (cap < 0) cap = 0;
    if (UI.renew_days > cap) UI.renew_days = cap;
    if (UI.renew_days < 1 && cap >= 1) UI.renew_days = cap;

    int64_t cost, rent = 0;
    if (!M.demo) {
        rent = rent_for_days(UI.renew_days);          // this name's days only
        cost = rent;
    } else {
        cost = M.year_cost * UI.renew_days / 365;
    }
    const char *why;
    const char *qw = why_queued(n, 1);
    if (qw) why = qw;
    else if (n->st == NS_RESERVED) why = TR(S_DLG_RENEW_WHY_RESERVED);
    else if (cap == 0) why = "";                      // the cap note below goes red
    else if (!M.demo && M.rate == 0) why = TR(S_DLG_WHY_NORATE);
    else why = why_pay(cost + UI_FEE_K);

    float w = 344, pad = 18, cw = w - 2 * pad;
    float h = pad + 30 + 22 + 42 + 10 + 18 + 18 + 12 + 26 + 12
            + why_h(why) + 38 + pad + 8;
    struct nk_rect r = dlg_begin(ctx, screen, w, h, C_BORDER);
    float x = r.x + pad, xr = r.x + w - pad, y = r.y + pad;
    char b[80];

    dlg_title(ctx, x, y, TR(S_DLG_RENEW_TITLE), n->name, C_TEXT, C_ACCENT);
    y += 32;
    char d1[32], d2[24];
    fmt_date_long(d1, sizeof d1, n->expiry);
    fmt_days_left(d2, sizeof d2, n->expiry - M.now);
    snprintf(b, sizeof b, "%s · %s", d1, d2);
    ui_kv_row(ctx, x, xr, y, TR(S_DLG_RENEW_EXPIRES), b, C_DIM, C_TEXT);
    y += 24;

    // add-days row with cap-respecting max
    struct nk_rect box = nk_rect(x, y, cw, 40);
    dk_card(ctx, box, 8, C_INPUT, C_BORDER);
    dk_text(ctx, F_PH14, x + 12, y + 9, C_DIM, TR(S_DLG_RENEW_ADD));
    snprintf(b, sizeof b, "%d", UI.renew_days);
    dk_text(ctx, F_SM16, x + 48, y + 10, C_TEXT, b);
    dk_text(ctx, F_PH14, x + 48 + dk_w(F_SM16, b) + 8, y + 9, C_DIM, TR(S_DLG_DAYS));
    struct nk_rect up = nk_rect(box.x + box.w - 78, y + 4, 20, 32);
    struct nk_rect dn = nk_rect(box.x + box.w - 56, y + 4, 20, 32);
    dk_text_c(ctx, F_SM10, up, dk_hot(ctx, up) ? C_TEXT : C_GHOST, "\xE2\x96\xB4");
    dk_text_c(ctx, F_SM10, dn, dk_hot(ctx, dn) ? C_TEXT : C_GHOST, "\xE2\x96\xBE");
    if (dk_click(ctx, up)) UI.renew_days = UI.renew_days + 30 > cap ? cap : UI.renew_days + 30;
    if (dk_click(ctx, dn)) UI.renew_days = UI.renew_days - 30 < 1 ? 1 : UI.renew_days - 30;
    struct nk_rect mx = nk_rect(box.x + box.w - 34, y + 10, 26, 18);
    dk_line_rect(ctx, mx, 5, C_ACCENT);
    dk_text_c(ctx, F_SM9, mx, C_ACCENT, TR(S_DLG_MAX));
    if (dk_click(ctx, mx)) UI.renew_days = cap;
    y += 48;
    if (cap == 0) {
        dk_text(ctx, F_SM10, x, y, C_RED, TR(S_DLG_RENEW_ATCAP));
        y += 18;
    } else {
        snprintf(b, sizeof b, TR(S_DLG_RENEW_CAP_FMT), cap);
        dk_text(ctx, F_SM10, x, y, C_GHOST, b);
        y += 18;
    }

    char cb[48];
    fmt_amount4_sp(cb, sizeof cb, cost);
    ui_kv_row(ctx, x, xr, y, TR(S_DLG_RENEW_COST), cb, C_GHOST, C_DIM);
    y += 18;
    fee_total(ctx, x, xr, &y, UI_FEE_K, cost + UI_FEE_K, C_ACCENT);

    float by = r.y + h - pad - 38;
    why_line(ctx, x, by, why);
    int act = dlg_pair_gated(ctx, x, by, cw, TR(S_CANCEL), TR(S_DLG_RENEW_OK), BTN_ACCENT, 1.0f, why);
    if (act == 1) close_dlg();
    if (act == 2 && !why) {
        if (!M.demo) {
            char one[1][24];            // §3.5 selective, one flag: the rent
            snprintf(one[0], sizeof one[0], "%s", n->name);
            ops_renew_sel(one, 1, rent);// water-fills THIS name only
        } else {
            n->expiry += (int64_t)UI.renew_days * 86400;
            M.balance -= cost + UI_FEE_K;
        }
        close_dlg();
    }
}

// ── batch renew — every name individually capped, at-cap auto-skipped (4b) ───
// Live rides §3.5 in either shape, always ONE tx and one fee: from the
// selection bar it's the SELECTIVE bitmap (rent water-fills exactly the
// chosen names); from "renew all names" it's the bare whole-set water-fill.
static void d_batch_renew(struct nk_context *ctx, struct nk_rect screen) {
    int idxs[16], nsel = 0;
    int sel_scope = M.demo || UI.renew_sel;                // else: the whole set
    int64_t total_cost = 0, total_days = 0;
    for (int i = 0; i < M.nnames && i < 16; i++) {
        if (M.names[i].st == NS_CLAIMING) continue;        // not on-chain yet
        if (!M.demo && M.names[i].pending) {
            int p = M.names[i].pending;                    // leaving the set before
            int leaves = p == OPS_PEND_RELEASE || p == OPS_PEND_TRANSFER ||
                         p == OPS_PEND_CLAIM || p == OPS_PEND_OTHER;
            if (sel_scope || leaves) continue;             // this renew folds → skip;
        }                                                  // a queued sell still renews
        if (sel_scope) {
            if (!(UI.sel_mask & (1u << i))) continue;
            if (M.names[i].st == NS_RESERVED) continue;
        }
        int add = 365 - (int)days_remaining(M.names[i].expiry);
        if (add <= 0) continue;                            // at cap → auto-skip
        idxs[nsel++] = i;
        total_days += add;
        total_cost += M.demo ? M.year_cost * add / 365
                             : rent_for_days(add);         // per-row display
    }
    int64_t rent = rent_for_days(total_days);              // live: one burn
    if (!M.demo) total_cost = rent;
    int nfee = M.demo ? nsel : 1;                          // live: ONE tx
    int64_t total = total_cost + (int64_t)UI_FEE_K * nfee;
    const char *why;
    if (nsel == 0) why = TR(S_DLG_BRENEW_WHY_NONE);
    else if (!M.demo && M.rate == 0) why = TR(S_DLG_WHY_NORATE);
    else why = why_pay(total);
    float w = 364, pad = 18, cw = w - 2 * pad;
    float list_h = (float)(nsel < 3 ? nsel : 3) * 34 + 2;
    float h = pad + 30 + 10 + list_h + 14 + 18 + 12 + 26 + why_h(why) + 12 + 38 + pad;
    struct nk_rect r = dlg_begin(ctx, screen, w, h, C_BORDER);
    float x = r.x + pad, xr = r.x + w - pad, y = r.y + pad;
    char b[64], t[80];

    snprintf(t, sizeof t, TR(S_DLG_BRENEW_TITLE_FMT), nsel, nsel == 1 ? "" : "s");
    dk_text(ctx, F_PH22, x, y, C_TEXT, t);
    dk_text(ctx, F_SM11, x + dk_w(F_PH22, t) + 8, y + 8, C_GHOST, TR(S_DLG_BRENEW_CAP_NOTE));
    y += 34;

    struct nk_rect lst = nk_rect(x, y, cw, list_h);
    dk_card(ctx, lst, 8, C_BG, C_BORDER);
    static DkScroll sc;
    dk_scroll_begin(ctx, &sc, lst);
    float ly = lst.y + 1 - sc.scroll;
    for (int k = 0; k < nsel; k++) {
        MyName *n = &M.names[idxs[k]];
        int add = 365 - (int)days_remaining(n->expiry);
        dk_text(ctx, F_SM13, x + 11, ly + 9, C_TEXT, n->name);
        snprintf(b, sizeof b, TR(S_DLG_BRENEW_PLUSD_FMT), add);
        dk_text_r(ctx, F_SM11, xr - 92, ly + 10, C_GREEN, b);
        fmt_amount4_sp(b, sizeof b, M.demo ? M.year_cost * add / 365 : rent_for_days(add));
        dk_text_r(ctx, F_SM11, xr - 14, ly + 10, C_DIM, b);
        if (k < nsel - 1) dk_hline(ctx, x + 1, xr - 1, ly + 33, C_HAIR);
        ly += 34;
    }
    dk_scroll_end(ctx, &sc, lst, (float)nsel * 34 + 2, 0);
    y += list_h + 14;

    snprintf(t, sizeof t, TR(S_DLG_BRENEW_TOTAL_FMT), nsel, nsel == 1 ? "" : "s");
    char fb[56];
    fmt_amount_sp(b, sizeof b, (int64_t)UI_FEE_K * nfee);
    snprintf(fb, sizeof fb, "+%s", b);
    ui_kv_row(ctx, x, xr, y, nfee > 1 ? TR(S_DLG_FEE) : TR(S_DLG_FEE_ONETX),
              fb, C_GHOST, C_DIM);
    y += 18;
    dk_hline(ctx, x, xr, y + 2, C_BORDER);
    y += 9;
    dk_text(ctx, F_SM13, x, y, C_TEXT, t);
    fmt_amount4_sp(b, sizeof b, total);
    dk_text_r(ctx, F_SM14, xr, y - 1, C_ACCENT, b);

    snprintf(t, sizeof t, TR(S_DLG_BRENEW_OK_FMT), nsel);
    float by = r.y + h - pad - 38;
    why_line(ctx, x, by, why);
    int act = dlg_pair_gated(ctx, x, by, cw, TR(S_CANCEL), t, BTN_ACCENT, 1.4f, why);
    if (act == 1) close_dlg();
    if (act == 2 && !why) {
        if (!M.demo) {
            if (UI.renew_sel) {                 // §3.5 selective: just the picks
                char names[16][24];
                for (int k = 0; k < nsel; k++)
                    snprintf(names[k], sizeof names[k], "%s", M.names[idxs[k]].name);
                ops_renew_sel(names, nsel, rent);
            } else {
                ops_renew(rent);                // bare: water-fill the whole set
            }
        } else {
            for (int k = 0; k < nsel; k++) {
                MyName *n = &M.names[idxs[k]];
                int add = 365 - (int)days_remaining(n->expiry);
                n->expiry += (int64_t)add * 86400;
            }
            M.balance -= total;
        }
        UI.sel_mask = 0;
        close_dlg();
    }
}

// ── sell (3b) ────────────────────────────────────────────────────────────────
static void d_sell(struct nk_context *ctx, struct nk_rect screen) {
    MyName *n = &M.names[UI.name_target];
    UI.sell_price[UI.sell_price_len] = 0;
    int64_t price = 0;
    int pok = fmt_parse_amount(UI.sell_price, &price) && price > 0;
    // §5 executability floor (subsumes the 3-koinu SELL floor): below 2.0 the
    // 0.5% pay-leg is sub-dust — the listing could never be bid on OR reclaimed
    int exec = price >= UI_LIST_MIN_K;
    // the fold drops a SELL whose window (+2h reorg buffer) outlives the lease
    int64_t need_tail = (int64_t)UI.sell_days * 86400 + 7200;
    const char *why;
    const char *qw = why_queued(n, 0);
    if (qw) why = qw;
    else if (n->st != NS_OWNED) why = TR(S_DLG_WHY_MOVELOCK);
    else if (UI.sell_price_len == 0) why = "";
    else if (!pok) why = TR(S_DLG_WHY_BADPRICE);
    else if (!exec) why = TR(S_DLG_SELL_WHY_DUST);
    else if (n->expiry - M.now < need_tail) why = TR(S_DLG_SELL_WHY_SHORT);
    else why = why_pay(UI_FEE_K);

    float w = 344, pad = 18, cw = w - 2 * pad;
    float h = pad + 30 + 20 + 40 + 12 + 20 + 40 + 14 + 20 + why_h(why) + 12 + 38 + pad;
    struct nk_rect r = dlg_begin(ctx, screen, w, h, C_BORDER);
    float x = r.x + pad, xr = r.x + w - pad, y = r.y + pad;
    char b[48];

    dlg_title(ctx, x, y, TR(S_DLG_SELL_TITLE), n->name, C_TEXT, C_ACCENT);
    y += 34;
    dk_text(ctx, F_PH14, x, y, C_DIM, TR(S_DLG_PRICE));
    y += 20;
    struct nk_rect pr = nk_rect(x, y, cw, 38);
    dk_card(ctx, pr, 8, C_INPUT, UI.sell_price_len && (!pok || !exec) ? C_RED : C_BORDER);
    dk_text(ctx, F_SM13, x + 12, y + 11, C_GHOST, GLY_P);
    ui_edit(ctx, nk_rect(x + 30, y + 4, cw - 40, 30), UI.sell_price, &UI.sell_price_len,
            sizeof UI.sell_price - 1, TR(S_DLG_SELL_PRICE_PH), F_SM16, 1);
    y += 50;
    dk_text(ctx, F_PH14, x, y, C_DIM, TR(S_DLG_SELL_WINDOW));
    y += 20;
    struct nk_rect wr = nk_rect(x, y, cw, 38);
    dk_card(ctx, wr, 8, C_INPUT, C_BORDER);
    dk_text(ctx, F_PH14, x + 12, y + 8, C_DIM, TR(S_DLG_SELL_LISTFOR));
    snprintf(b, sizeof b, "%d", UI.sell_days);
    dk_text(ctx, F_SM16, x + 68, y + 9, C_TEXT, b);
    dk_text(ctx, F_PH14, x + 68 + dk_w(F_SM16, b) + 8, y + 8, C_DIM, TR(S_DLG_DAYS));
    struct nk_rect up = nk_rect(wr.x + wr.w - 74, y + 3, 20, 32);
    struct nk_rect dn = nk_rect(wr.x + wr.w - 52, y + 3, 20, 32);
    dk_text_c(ctx, F_SM10, up, dk_hot(ctx, up) ? C_TEXT : C_GHOST, "\xE2\x96\xB4");
    dk_text_c(ctx, F_SM10, dn, dk_hot(ctx, dn) ? C_TEXT : C_GHOST, "\xE2\x96\xBE");
    if (dk_click(ctx, up)) UI.sell_days = UI.sell_days >= 30 ? 30 : UI.sell_days + 5;
    if (dk_click(ctx, dn)) UI.sell_days = UI.sell_days <= 5 ? 1 : UI.sell_days - 5;
    dk_text_r(ctx, F_SM9, wr.x + wr.w - 10, y + 12, C_GHOST, TR(S_DLG_SELL_MAX30));
    y += 52;
    char fb[56];
    fmt_amount_sp(b, sizeof b, UI_FEE_K);
    snprintf(fb, sizeof fb, "+%s", b);
    dk_hline(ctx, x, xr, y - 2, C_BORDER);
    ui_kv_row(ctx, x, xr, y + 6, TR(S_DLG_FEE), fb, C_GHOST, C_DIM);

    float by = r.y + h - pad - 38;
    why_line(ctx, x, by, why);
    int act = dlg_pair_gated(ctx, x, by, cw, TR(S_CANCEL), TR(S_DLG_SELL_OK), BTN_ACCENT, 1.0f, why);
    if (act == 1) close_dlg();
    if (act == 2 && !why) {
        if (!M.demo) {
            ops_sell(n->name, (uint64_t)price, (uint32_t)UI.sell_days * 86400u);
        } else {
            n->st = NS_LISTED;
            n->list_price = price;
            n->list_window_end = M.now + (int64_t)UI.sell_days * 86400;
            M.balance -= UI_FEE_K;
        }
        close_dlg();
    }
}

// ── offer — §3.7 SELL_TO: a directed sale to one buyer (3b) ──────────────────
// Exclusive by construction: only the named buyer can PAY, within the fixed
// 2 h window; no deposit machinery, no cancel — a stale offer self-expires.
static void d_offer(struct nk_context *ctx, struct nk_rect screen) {
    MyName *n = &M.names[UI.name_target];
    UI.send_to[UI.send_to_len] = 0;
    UI.sell_price[UI.sell_price_len] = 0;
    int aok = wallet_addr_valid(UI.send_to);
    int64_t price = 0;
    int pok = fmt_parse_amount(UI.sell_price, &price) && price >= 1;
    const char *why;
    const char *qw = why_queued(n, 0);
    if (qw) why = qw;
    else if (n->st != NS_OWNED) why = TR(S_DLG_WHY_MOVELOCK);
    else if (UI.send_to_len == 0 || UI.sell_price_len == 0) why = "";
    else if (!aok) {
        snprintf(why_buf, sizeof why_buf, TR(S_DLG_WHY_BADADDR_FMT), wallet_coin());
        why = why_buf;
    }
    else if (!strcmp(UI.send_to, M.address)) why = TR(S_DLG_WHY_OWNADDR);
    else if (!pok) why = TR(S_DLG_WHY_BADPRICE);
    // §5: PAY sends the full price in ONE output — sub-dust could never relay
    else if (price < UI_DUST_K) why = TR(S_DLG_OFFER_WHY_DUST);
    // fold rule: DIRECT_WINDOW + REORG_BUFFER (2 h + 2 h) must fit the lease
    else if (n->expiry - M.now < 14400) why = TR(S_DLG_OFFER_WHY_SHORT);
    else why = why_pay(UI_FEE_K);

    float w = 344, pad = 18, cw = w - 2 * pad;
    float h = pad + 30 + 20 + 40 + 12 + 20 + 40 + 14 + 20 + 22 + why_h(why) + 12 + 38 + pad;
    struct nk_rect r = dlg_begin(ctx, screen, w, h, C_BORDER);
    float x = r.x + pad, xr = r.x + w - pad, y = r.y + pad;
    char b[48];

    dlg_title(ctx, x, y, TR(S_DLG_OFFER_TITLE), n->name, C_TEXT, C_ACCENT);
    y += 34;
    dk_text(ctx, F_PH14, x, y, C_DIM, TR(S_DLG_TO_ADDR));
    y += 20;
    struct nk_rect tr = nk_rect(x, y, cw, 38);
    dk_card(ctx, tr, 8, C_INPUT, UI.send_to_len && !aok ? C_RED : C_BORDER);
    ui_edit(ctx, nk_rect(x + 6, y + 4, cw - 12, 30), UI.send_to, &UI.send_to_len,
            sizeof UI.send_to - 1, TR(S_DLG_ADDR_PH), F_SM13, 1);
    if (UI.send_to_len && aok)
        dk_text_r(ctx, F_SM10, xr - 8, y + 12, C_GREEN, "\xE2\x9C\x93");
    y += 52;
    dk_text(ctx, F_PH14, x, y, C_DIM, TR(S_DLG_PRICE));
    y += 20;
    struct nk_rect pr = nk_rect(x, y, cw, 38);
    dk_card(ctx, pr, 8, C_INPUT, UI.sell_price_len && !pok ? C_RED : C_BORDER);
    dk_text(ctx, F_SM13, x + 12, y + 11, C_GHOST, GLY_P);
    ui_edit(ctx, nk_rect(x + 30, y + 4, cw - 40, 30), UI.sell_price, &UI.sell_price_len,
            sizeof UI.sell_price - 1, "0.0", F_SM16, 1);
    y += 52;
    char fb[56];
    fmt_amount_sp(b, sizeof b, UI_FEE_K);
    snprintf(fb, sizeof fb, "+%s", b);
    dk_hline(ctx, x, xr, y - 2, C_BORDER);
    ui_kv_row(ctx, x, xr, y + 6, TR(S_DLG_FEE), fb, C_GHOST, C_DIM);
    y += 26;
    dk_text(ctx, F_SM10, x, y, C_GHOST,
            TR(S_DLG_OFFER_NOTE));

    float by = r.y + h - pad - 38;
    why_line(ctx, x, by, why);
    int act = dlg_pair_gated(ctx, x, by, cw, TR(S_CANCEL), TR(S_DLG_OFFER_OK), BTN_ACCENT, 1.0f, why);
    if (act == 1) close_dlg();
    if (act == 2 && !why) {
        if (!M.demo) {
            uint8_t to[20];
            if (wallet_addr_decode(UI.send_to, to))
                ops_offer(n->name, to, (uint64_t)price);
        } else {
            n->st = NS_OFFERED;
            n->offer_price = price;
            n->reserve_end = M.now + 7200;
            snprintf(n->offered_to, sizeof n->offered_to, "%.10s\xE2\x80\xA6", UI.send_to);
            M.balance -= UI_FEE_K;
        }
        close_dlg();
    }
}

// ── transfer ─────────────────────────────────────────────────────────────────
// §3.6's SELECTIVE form: [target][anchor][flags] moves exactly this name —
// the button does what it says. (The bare all-form, ops_transfer, stays in
// the seam for a future move-the-whole-wallet action.)
static void d_transfer(struct nk_context *ctx, struct nk_rect screen) {
    MyName *n = &M.names[UI.name_target];
    UI.send_to[UI.send_to_len] = 0;
    int aok = wallet_addr_valid(UI.send_to);
    const char *why;
    const char *qw = why_queued(n, 0);
    if (qw) why = qw;
    else if (n->st != NS_OWNED) why = TR(S_DLG_WHY_MOVELOCK);
    else if (UI.send_to_len == 0) why = "";
    else if (!aok) {
        snprintf(why_buf, sizeof why_buf, TR(S_DLG_WHY_BADADDR_FMT), wallet_coin());
        why = why_buf;
    }
    else if (!strcmp(UI.send_to, M.address)) why = TR(S_DLG_WHY_OWNADDR);
    else why = why_pay(UI_FEE_K);

    float w = 344, pad = 18, cw = w - 2 * pad;
    float h = pad + 30 + 20 + 40 + 14 + 20 + why_h(why) + 12 + 38 + pad;
    struct nk_rect r = dlg_begin(ctx, screen, w, h, C_BORDER);
    float x = r.x + pad, xr = r.x + w - pad, y = r.y + pad;

    dlg_title(ctx, x, y, TR(S_DLG_TRANSFER_TITLE), n->name, C_TEXT, C_ACCENT);
    y += 34;
    dk_text(ctx, F_PH14, x, y, C_DIM, TR(S_DLG_TO_ADDR));
    y += 20;
    struct nk_rect tr = nk_rect(x, y, cw, 38);
    dk_card(ctx, tr, 8, C_INPUT, UI.send_to_len && !aok ? C_RED : C_BORDER);
    ui_edit(ctx, nk_rect(x + 6, y + 4, cw - 12, 30), UI.send_to, &UI.send_to_len,
            sizeof UI.send_to - 1, TR(S_DLG_ADDR_PH), F_SM13, 1);
    if (UI.send_to_len && aok)
        dk_text_r(ctx, F_SM10, xr - 8, y + 12, C_GREEN, "\xE2\x9C\x93");
    y += 52;
    char b[48], fb[56];
    fmt_amount_sp(b, sizeof b, UI_FEE_K);
    snprintf(fb, sizeof fb, "+%s", b);
    dk_hline(ctx, x, xr, y - 2, C_BORDER);
    ui_kv_row(ctx, x, xr, y + 6, TR(S_DLG_FEE), fb, C_GHOST, C_DIM);

    float by = r.y + h - pad - 38;
    why_line(ctx, x, by, why);
    int act = dlg_pair_gated(ctx, x, by, cw, TR(S_CANCEL), TR(S_DLG_TRANSFER_OK), BTN_ACCENT, 1.0f, why);
    if (act == 1) close_dlg();
    if (act == 2 && !why) {
        if (!M.demo) {
            uint8_t to[20];
            char one[1][24];
            snprintf(one[0], sizeof one[0], "%s", n->name);
            if (wallet_addr_decode(UI.send_to, to)) ops_transfer_sel(one, 1, to);
        } else {
            names_remove(UI.name_target);
            M.balance -= UI_FEE_K;
        }
        close_dlg();
    }
}

// ── release — destructive, plainly warned (3b) ───────────────────────────────
// whole-zone clear (DNS screen): a free, owner-signed op that voids every
// record + tombstone below its anchor on every mirror. Destructive-styled
// because it empties the zone, but costs nothing and needs no transaction.
static void d_dns_clear(struct nk_context *ctx, struct nk_rect screen) {
    int ni = ui_dns_pick_name();
    if (ni < 0) { close_dlg(); return; }
    const char *apex = M.names[ni].name;
    float w = 344, pad = 18, cw = w - 2 * pad;
    float body_h = dk_wrap(NULL, F_PH14, 0, 0, cw, C_DIM,
        TR(S_DLG_DNSCLEAR_BODY), 1.35f);
    float h = pad + 30 + 8 + body_h + 16 + 38 + pad;
    struct nk_rect rr = dlg_begin(ctx, screen, w, h, C_RED);
    float x = rr.x + pad, y = rr.y + pad;
    char t[80];

    snprintf(t, sizeof t, "%s", TR(S_DLG_DNSCLEAR_TITLE));
    dk_text(ctx, F_PH22, x, y, C_RED, t);
    dk_text(ctx, F_SM16, x + dk_w(F_PH22, t) + 8, y + 5, C_RED, apex);
    dk_text(ctx, F_PH22, x + dk_w(F_PH22, t) + 12 + dk_w(F_SM16, apex), y, C_RED, "?");
    y += 34;
    y = dk_wrap(ctx, F_PH14, x, y, cw, C_DIM,
        TR(S_DLG_DNSCLEAR_BODY), 1.35f) + 12;

    float by = rr.y + h - pad - 38;
    int act = dlg_pair_gated(ctx, x, by, cw, TR(S_DLG_DNSCLEAR_CANCEL),
                             TR(S_DLG_DNSCLEAR_OK), BTN_RED, 1.0f, NULL);
    if (act == 1) close_dlg();
    if (act == 2) {
        if (!M.demo) dnsnet_publish_clear(apex);
        close_dlg();
    }
}

static void d_release(struct nk_context *ctx, struct nk_rect screen) {
    MyName *n = &M.names[UI.name_target];
    const char *qw = why_queued(n, 0);
    const char *why = qw ? qw
        : n->st != NS_OWNED ? TR(S_DLG_WHY_MOVELOCK)
        : why_pay(UI_FEE_K);
    float w = 344, pad = 18, cw = w - 2 * pad;
    float body_h = dk_wrap(NULL, F_PH14, 0, 0, cw, C_DIM,
        TR(S_DLG_RELEASE_BODY), 1.35f);
    float h = pad + 30 + 8 + body_h + 14 + 20 + why_h(why) + 12 + 38 + pad;
    struct nk_rect rr = dlg_begin(ctx, screen, w, h, C_RED);
    float x = rr.x + pad, xr = rr.x + w - pad, y = rr.y + pad;
    char t[80];

    snprintf(t, sizeof t, "%s", TR(S_DLG_RELEASE_TITLE));
    dk_text(ctx, F_PH22, x, y, C_RED, t);
    dk_text(ctx, F_SM16, x + dk_w(F_PH22, t) + 8, y + 5, C_RED, n->name);
    dk_text(ctx, F_PH22, x + dk_w(F_PH22, t) + 12 + dk_w(F_SM16, n->name), y, C_RED, "?");
    y += 34;
    y = dk_wrap(ctx, F_PH14, x, y, cw, C_DIM,
        TR(S_DLG_RELEASE_BODY), 1.35f) + 10;
    char b[48], fb[56];
    fmt_amount_sp(b, sizeof b, UI_FEE_K);
    snprintf(fb, sizeof fb, "+%s", b);
    dk_hline(ctx, x, xr, y, C_BORDER);
    ui_kv_row(ctx, x, xr, y + 8, TR(S_DLG_FEE), fb, C_GHOST, C_DIM);

    float by = rr.y + h - pad - 38;
    why_line(ctx, x, by, why);
    int act = dlg_pair_gated(ctx, x, by, cw, TR(S_DLG_RELEASE_CANCEL), TR(S_DLG_RELEASE_OK), BTN_RED, 1.0f, why);
    if (act == 1) close_dlg();
    if (act == 2 && !why) {
        if (!M.demo) {
            ops_release(n->name);       // §3.6 selective bitmap — just this name
        } else {
            names_remove(UI.name_target);
            M.balance -= UI_FEE_K;
        }
        close_dlg();
    }
}

// ── batch release — the picks leave in ONE §3.5 bitmap tx, one fee (3a) ──────
static void d_batch_release(struct nk_context *ctx, struct nk_rect screen) {
    int idxs[16], k = 0;
    for (int i = 0; i < M.nnames && i < 16; i++) {
        if (!(UI.sel_mask & (1u << i))) continue;
        MyName *n = &M.names[i];
        if (n->st != NS_OWNED || n->pending) continue;  // movement locks + the matrix
        idxs[k++] = i;
    }
    if (!k) { close_dlg(); return; }
    const char *why = why_pay(UI_FEE_K);

    float list_h = (float)(k < 5 ? k : 5) * 34 + 2;
    float w = 344, pad = 18, cw = w - 2 * pad;
    float body_h = dk_wrap(NULL, F_PH14, 0, 0, cw, C_DIM,
        TR(S_DLG_BRELEASE_BODY), 1.35f);
    float h = pad + 30 + 8 + list_h + 12 + body_h + 14 + 20 + why_h(why) + 12 + 38 + pad;
    struct nk_rect rr = dlg_begin(ctx, screen, w, h, C_RED);
    float x = rr.x + pad, xr = rr.x + w - pad, y = rr.y + pad;
    char b[64], t[64];

    snprintf(t, sizeof t, TR(S_DLG_BRELEASE_TITLE_FMT), k, k == 1 ? "" : "s");
    dk_text(ctx, F_PH22, x, y, C_RED, t);
    y += 34;
    struct nk_rect lst = nk_rect(x, y, cw, list_h);
    dk_card(ctx, lst, 8, C_BG, C_BORDER);
    static DkScroll sc;
    dk_scroll_begin(ctx, &sc, lst);
    float ly = lst.y + 1 - sc.scroll;
    for (int j = 0; j < k; j++) {
        MyName *n = &M.names[idxs[j]];
        dk_text(ctx, F_SM13, x + 11, ly + 9, C_TEXT, n->name);
        char dl[24];                                    // the lease being forfeited
        fmt_days_left(dl, sizeof dl, n->expiry - M.now);
        dk_text_r(ctx, F_SM11, xr - 14, ly + 10, C_DIM, dl);
        if (j < k - 1) dk_hline(ctx, x + 1, xr - 1, ly + 33, C_HAIR);
        ly += 34;
    }
    dk_scroll_end(ctx, &sc, lst, (float)k * 34 + 2, 0);
    y += list_h + 12;
    y = dk_wrap(ctx, F_PH14, x, y, cw, C_DIM,
        TR(S_DLG_BRELEASE_BODY), 1.35f) + 10;
    char fb[56];
    fmt_amount_sp(b, sizeof b, UI_FEE_K);
    snprintf(fb, sizeof fb, "+%s", b);
    dk_hline(ctx, x, xr, y, C_BORDER);
    ui_kv_row(ctx, x, xr, y + 8, TR(S_DLG_FEE_ONETX), fb, C_GHOST, C_DIM);

    snprintf(t, sizeof t, TR(S_DLG_BRELEASE_OK_FMT), k);
    float by = rr.y + h - pad - 38;
    why_line(ctx, x, by, why);
    int act = dlg_pair_gated(ctx, x, by, cw, TR(S_DLG_BRELEASE_CANCEL), t, BTN_RED, 1.4f, why);
    if (act == 1) close_dlg();
    if (act == 2 && !why) {
        if (!M.demo) {
            char names[16][24];
            for (int j = 0; j < k; j++)
                snprintf(names[j], sizeof names[j], "%s", M.names[idxs[j]].name);
            ops_release_multi(names, k);
        } else {
            for (int j = k - 1; j >= 0; j--)    // descending — names_remove shifts
                names_remove(idxs[j]);
            M.balance -= UI_FEE_K;
        }
        UI.sel_mask = 0;
        close_dlg();
    }
}

// ── batch transfer — the picks gift in ONE §3.5 bitmap tx, one fee (3a) ──────
// Selective §3.6: [target][anchor][flags] moves exactly the checked names.
// Gift-only and irreversible — the note says so before the button goes live.
static void d_batch_transfer(struct nk_context *ctx, struct nk_rect screen) {
    const char *note = TR(S_DLG_BTRANSFER_NOTE);
    int idxs[16], k = 0;
    for (int i = 0; i < M.nnames && i < 16; i++) {
        if (!(UI.sel_mask & (1u << i))) continue;
        MyName *n = &M.names[i];
        if (n->st != NS_OWNED || n->pending) continue;  // movement locks + the matrix
        idxs[k++] = i;
    }
    if (!k) { close_dlg(); return; }
    UI.send_to[UI.send_to_len] = 0;
    int aok = wallet_addr_valid(UI.send_to);
    const char *why;
    if (UI.send_to_len == 0) why = "";
    else if (!aok) {
        snprintf(why_buf, sizeof why_buf, TR(S_DLG_WHY_BADADDR_FMT), wallet_coin());
        why = why_buf;
    }
    else if (!strcmp(UI.send_to, M.address)) why = TR(S_DLG_WHY_OWNADDR);
    else why = why_pay(UI_FEE_K);

    float list_h = (float)(k < 5 ? k : 5) * 34 + 2;
    float w = 344, pad = 18, cw = w - 2 * pad;
    float body_h = dk_wrap(NULL, F_PH14, 0, 0, cw, C_DIM, note, 1.35f);
    float h = pad + 30 + 8 + list_h + 12 + 20 + 40 + 12 + body_h + 14 + 20
            + why_h(why) + 12 + 38 + pad;
    struct nk_rect rr = dlg_begin(ctx, screen, w, h, C_BORDER);
    float x = rr.x + pad, xr = rr.x + w - pad, y = rr.y + pad;
    char b[64], t[64];

    snprintf(t, sizeof t, TR(S_DLG_BTRANSFER_TITLE_FMT), k, k == 1 ? "" : "s");
    dk_text(ctx, F_PH22, x, y, C_TEXT, t);
    y += 34;
    struct nk_rect lst = nk_rect(x, y, cw, list_h);
    dk_card(ctx, lst, 8, C_BG, C_BORDER);
    static DkScroll sc;
    dk_scroll_begin(ctx, &sc, lst);
    float ly = lst.y + 1 - sc.scroll;
    for (int j = 0; j < k; j++) {
        MyName *n = &M.names[idxs[j]];
        dk_text(ctx, F_SM13, x + 11, ly + 9, C_TEXT, n->name);
        char dl[24];                                    // the lease that conveys
        fmt_days_left(dl, sizeof dl, n->expiry - M.now);
        dk_text_r(ctx, F_SM11, xr - 14, ly + 10, C_DIM, dl);
        if (j < k - 1) dk_hline(ctx, x + 1, xr - 1, ly + 33, C_HAIR);
        ly += 34;
    }
    dk_scroll_end(ctx, &sc, lst, (float)k * 34 + 2, 0);
    y += list_h + 12;
    dk_text(ctx, F_PH14, x, y, C_DIM, TR(S_DLG_TO_ADDR));
    y += 20;
    struct nk_rect tr = nk_rect(x, y, cw, 38);
    dk_card(ctx, tr, 8, C_INPUT, UI.send_to_len && !aok ? C_RED : C_BORDER);
    ui_edit(ctx, nk_rect(x + 6, y + 4, cw - 12, 30), UI.send_to, &UI.send_to_len,
            sizeof UI.send_to - 1, TR(S_DLG_ADDR_PH), F_SM13, 1);
    if (UI.send_to_len && aok)
        dk_text_r(ctx, F_SM10, xr - 8, y + 12, C_GREEN, "\xE2\x9C\x93");
    y += 50;
    y = dk_wrap(ctx, F_PH14, x, y, cw, C_DIM, note, 1.35f) + 10;
    char fb[56];
    fmt_amount_sp(b, sizeof b, UI_FEE_K);
    snprintf(fb, sizeof fb, "+%s", b);
    dk_hline(ctx, x, xr, y, C_BORDER);
    ui_kv_row(ctx, x, xr, y + 8, TR(S_DLG_FEE_ONETX), fb, C_GHOST, C_DIM);

    snprintf(t, sizeof t, TR(S_DLG_BTRANSFER_OK_FMT), k);
    float by = rr.y + h - pad - 38;
    why_line(ctx, x, by, why);
    int act = dlg_pair_gated(ctx, x, by, cw, TR(S_CANCEL), t, BTN_ACCENT, 1.4f, why);
    if (act == 1) close_dlg();
    if (act == 2 && !why) {
        if (!M.demo) {
            uint8_t to[20];
            char names[16][24];
            for (int j = 0; j < k; j++)
                snprintf(names[j], sizeof names[j], "%s", M.names[idxs[j]].name);
            if (wallet_addr_decode(UI.send_to, to)) ops_transfer_sel(names, k, to);
        } else {
            for (int j = k - 1; j >= 0; j--)    // descending — names_remove shifts
                names_remove(idxs[j]);
            M.balance -= UI_FEE_K;
        }
        UI.sel_mask = 0;
        close_dlg();
    }
}

// ── claim a name — two-tx cost surfaced, wait handled for you (3c) ───────────
static void d_claim(struct nk_context *ctx, struct nk_rect screen) {
    UI.claim_name[UI.claim_name_len] = 0;
    int syn = sm_name_valid(UI.claim_name, (size_t)UI.claim_name_len);
    int taken = 0;
    if (syn && M.demo) {          // what demo state knows of the namespace
        for (int i = 0; i < M.nnames && !taken; i++)
            taken = !strcmp(M.names[i].name, UI.claim_name);
        for (int i = 0; i < M.nlist && !taken; i++)
            taken = !strcmp(M.listings[i].name, UI.claim_name);
    } else if (syn && !M.demo) {  // the projection itself
        taken = engine_name_lookup(UI.claim_name, NULL, NULL) != 0;
    }
    int64_t burn = M.demo ? M.year_cost * UI.claim_days / 365
                          : rent_for_days(UI.claim_days);
    int64_t total = burn + 2 * UI_FEE_K;
    // §activation first: a commit mined below the activation height decodes
    // fine but never folds — the claim would wait on it forever and the fee
    // is burned for nothing. Dead confirm + the countdown until names go live.
    static char why_act[96];
    const char *why;
    if (!M.demo && M.activation && M.height && M.height < M.activation) {
        char blk[24]; fmt_thousands(blk, sizeof blk, M.activation);
        snprintf(why_act, sizeof why_act, TR(S_DLG_WHY_PREACT_FMT),
                 blk, (long long)(M.activation - M.height));
        why = why_act;
    }
    else if (UI.claim_name_len == 0) why = "";
    else if (!syn) why = TR(S_DLG_CLAIM_WHY_SYNTAX);
    else if (taken) why = TR(S_DLG_CLAIM_WHY_TAKEN);
    else if (!M.demo && M.rate == 0) why = TR(S_DLG_WHY_NORATE);
    else why = why_pay(total);

    float w = 344, pad = 18, cw = w - 2 * pad;
    float note_h = dk_wrap(NULL, F_PH12, 0, 0, cw, C_GHOST,
        TR(S_DLG_CLAIM_NOTE), 1.35f);
    float h = pad + 30 + 20 + 40 + 12 + 20 + 40 + 12 + 18 + 18 + 12 + 26 + 8 + note_h
            + why_h(why) + 12 + 38 + pad;
    struct nk_rect r = dlg_begin(ctx, screen, w, h, C_BORDER);
    float x = r.x + pad, xr = r.x + w - pad, y = r.y + pad;
    char b[64];

    dk_text(ctx, F_PH22, x, y, C_TEXT, TR(S_DLG_CLAIM_TITLE));
    y += 34;
    dk_text(ctx, F_PH14, x, y, C_DIM, TR(S_DLG_CLAIM_NAME));
    y += 20;
    struct nk_rect nr = nk_rect(x, y, cw, 38);
    dk_card(ctx, nr, 8, C_INPUT, UI.claim_name_len && !syn ? C_RED : C_BORDER);
    struct nk_rect er = nk_rect(x + 6, y + 4, cw - 12, 30);
    ui_edit(ctx, er, UI.claim_name, &UI.claim_name_len,
            sizeof UI.claim_name - 1, TR(S_DLG_CLAIM_NAME_PH), F_SM16, 1);
    // ghost TLD completes what's being typed: name → name.pepe (after the
    // placeholder too, so the empty field reads "yourname.pepe"). +5 mirrors
    // ui_edit's bare-mode text anchor.
    {
        const char *base = UI.claim_name_len ? UI.claim_name : TR(S_DLG_CLAIM_NAME_PH);
        dk_text(ctx, F_SM16, er.x + 5 + dk_w(F_SM16, base),
                er.y + (er.h - theme_lineh(F_SM16)) / 2, C_GHOST, APP_DOT_TLD);
    }
    if (UI.claim_name_len && syn && !taken)
        dk_text_r(ctx, F_SM10, xr - 8, y + 12, C_GREEN, "\xE2\x9C\x93");
    y += 50;
    dk_text(ctx, F_PH14, x, y, C_DIM, TR(S_DLG_CLAIM_LEASEFOR));
    y += 20;
    struct nk_rect lr = nk_rect(x, y, cw, 38);
    dk_card(ctx, lr, 8, C_INPUT, C_BORDER);
    snprintf(b, sizeof b, "%d", UI.claim_days);
    dk_text(ctx, F_SM16, x + 12, y + 9, C_TEXT, b);
    dk_text(ctx, F_PH14, x + 12 + dk_w(F_SM16, b) + 8, y + 8, C_DIM, TR(S_DLG_DAYS));
    struct nk_rect up = nk_rect(lr.x + lr.w - 74, y + 3, 20, 32);
    struct nk_rect dn = nk_rect(lr.x + lr.w - 52, y + 3, 20, 32);
    dk_text_c(ctx, F_SM10, up, dk_hot(ctx, up) ? C_TEXT : C_GHOST, "\xE2\x96\xB4");
    dk_text_c(ctx, F_SM10, dn, dk_hot(ctx, dn) ? C_TEXT : C_GHOST, "\xE2\x96\xBE");
    if (dk_click(ctx, up)) UI.claim_days = UI.claim_days + 30 > 365 ? 365 : UI.claim_days + 30;
    if (dk_click(ctx, dn)) UI.claim_days = UI.claim_days - 30 < 1 ? 1 : UI.claim_days - 30;
    struct nk_rect mx = nk_rect(lr.x + lr.w - 34, y + 10, 26, 18);
    dk_line_rect(ctx, mx, 5, C_BORDER);
    dk_text_c(ctx, F_SM9, mx, C_GHOST, TR(S_DLG_MAX));
    if (dk_click(ctx, mx)) UI.claim_days = 365;
    y += 50;

    fmt_amount4_sp(b, sizeof b, burn);
    ui_kv_row(ctx, x, xr, y, TR(S_DLG_CLAIM_BURN), b, C_DIM, C_ACCENT);
    y += 18;
    char fb[56];
    fmt_amount_sp(b, sizeof b, 2 * UI_FEE_K);
    snprintf(fb, sizeof fb, "+%s", b);
    ui_kv_row(ctx, x, xr, y, TR(S_DLG_CLAIM_FEES2), fb, C_DIM, C_DIM);
    y += 18;
    dk_hline(ctx, x, xr, y + 2, C_BORDER);
    y += 9;
    dk_text(ctx, F_SM13, x, y, C_TEXT, TR(S_DLG_TOTAL));
    fmt_amount4_sp(b, sizeof b, total);
    dk_text_r(ctx, F_SM14, xr, y - 1, C_ACCENT, b);
    y += 26;
    y = dk_wrap(ctx, F_PH12, x, y, cw, C_GHOST,
        TR(S_DLG_CLAIM_NOTE), 1.35f);

    float by = r.y + h - pad - 38;
    why_line(ctx, x, by, why);
    int act = dlg_pair_gated(ctx, x, by, cw, TR(S_CANCEL), TR(S_DLG_CLAIM_OK), BTN_ACCENT, 1.0f, why);
    if (act == 1) close_dlg();
    if (act == 2 && !why) {
        if (!M.demo) {
            // commit broadcasts now; the claim auto-fires when it confirms
            // (ops_poll) and the name row arrives via the projection
            ops_claim(UI.claim_name, burn);
            close_dlg();
        } else if (M.nnames < 16) {
            MyName *n = &M.names[M.nnames++];
            memset(n, 0, sizeof *n);
            snprintf(n->name, sizeof n->name, "%s", UI.claim_name);
            n->st = NS_OWNED;
            n->expiry = M.now + (int64_t)UI.claim_days * 86400;
            n->bytes_left = ZONE_BUDGET;
            M.balance -= total;
            close_dlg();
        }
    }
}

// ── place bid — 1% non-refundable (3e) ───────────────────────────────────────
static void d_bid(struct nk_context *ctx, struct nk_rect screen) {
    if (UI.listing_target < 0 || UI.listing_target >= M.nlist) { close_dlg(); return; }
    Listing *l = &M.listings[UI.listing_target];
    int mine = l->is_mine;                       // §3.7: buying your OWN listing reclaims it
    int64_t burn = dep_leg(l->price);            // 0.5% burned
    int64_t dep = 2 * burn;                      // + 0.5% to the seller (self, when mine)
    int64_t rem = l->price - dep;                // the auto-settle's remainder leg
    int64_t total = l->price + 2 * UI_FEE_K;     // the WHOLE flow: reserve + settle
    const char *why;
    if (l->reserved_by_other) why = TR(S_DLG_BID_WHY_RESERVED);
    else if (l->window_end <= M.now) why = TR(S_DLG_BID_WHY_CLOSED);
    else if (l->pending) why = TR(S_DLG_WHY_QUEUED);
    // §5: a sub-dust pay-leg can't relay — the tx would broadcast, never mine
    else if (l->price < UI_LIST_MIN_K)
        why = mine ? TR(S_DLG_BID_WHY_MINE_DUST)
                   : TR(S_DLG_BID_WHY_DUST);
    else why = why_pay(total);      // must fund reserve AND settle up front —
                                    // the parked settle must always build

    float w = 344, pad = 18, cw = w - 2 * pad;
    float h = pad + 30 + 8 + 4 * 18 + 12 + 26 + 10 + 36 + why_h(why) + 12 + 38 + pad;
    struct nk_rect r = dlg_begin(ctx, screen, w, h, C_ACCENT);
    float x = r.x + pad, xr = r.x + w - pad, y = r.y + pad;
    char b[48];

    dlg_title(ctx, x, y, mine ? TR(S_DLG_TITLE_RECLAIM) : TR(S_DLG_TITLE_BUY), l->name, C_TEXT, C_ACCENT);
    y += 36;
    fmt_amount_sp(b, sizeof b, l->price);
    ui_kv_row(ctx, x, xr, y, TR(S_DLG_LIST_PRICE), b, C_DIM, C_TEXT);
    y += 18;
    fmt_amount_sp(b, sizeof b, dep);
    ui_kv_row(ctx, x, xr, y, mine ? TR(S_DLG_BID_DEP_MINE) : TR(S_DLG_BID_DEP),
              b, C_DIM, C_ACCENT);
    y += 18;
    fmt_amount_sp(b, sizeof b, rem);
    ui_kv_row(ctx, x, xr, y, mine ? TR(S_DLG_BID_REM_MINE) : TR(S_DLG_BID_REM),
              b, C_DIM, mine ? C_GREEN : C_TEXT);
    y += 18;
    char fb[56];
    fmt_amount_sp(b, sizeof b, 2 * UI_FEE_K);
    snprintf(fb, sizeof fb, "+%s", b);
    ui_kv_row(ctx, x, xr, y, TR(S_DLG_BID_FEES2), fb, C_GHOST, C_DIM);
    y += 18;
    dk_hline(ctx, x, xr, y + 2, C_BORDER);
    y += 9;
    dk_text(ctx, F_SM13, x, y, C_TEXT, TR(S_DLG_TOTAL));
    fmt_amount4_sp(b, sizeof b, total);
    dk_text_r(ctx, F_SM14, xr, y - 1, C_ACCENT, b);
    y += 24;
    y += 2;
    struct nk_rect warn = nk_rect(x, y, cw, 32);
    if (mine) {
        dk_line_rect(ctx, warn, 7, C_ACCENT);
        dk_text(ctx, F_PH12, x + 11, y + 9, C_ACCENT,
                TR(S_DLG_BID_NOTE_MINE));
    } else {
        dk_line_rect(ctx, warn, 7, C_RED);
        dk_text(ctx, F_PH12, x + 11, y + 9, C_RED,
                TR(S_DLG_BID_WARN));
    }

    float by = r.y + h - pad - 38;
    why_line(ctx, x, by, why);
    int act = dlg_pair_gated(ctx, x, by, cw, TR(S_CANCEL), mine ? TR(S_DLG_BID_OK_MINE) : TR(S_DLG_BID_OK),
                             BTN_ACCENT, 1.0f, why);
    if (act == 1) close_dlg();
    if (act == 2 && !why) {
        if (!M.demo) {
            // one action: reserve now, the settle parks and fires when the
            // reserve folds with us as buyer (ops.c reserve→settle park)
            ops_reserve(l->name);
        } else {                        // demo mirrors the whole auto-flow
            int ex = -1;
            for (int i = 0; i < M.nnames; i++)
                if (!strcmp(M.names[i].name, l->name)) { ex = i; break; }
            if (ex >= 0) {                          // reclaim: back to plain owned
                M.names[ex].st = NS_OWNED;
                M.names[ex].list_price = 0;
                M.names[ex].list_window_end = 0;
            } else if (M.nnames < 16) {             // bought: the lease conveys
                MyName *n = &M.names[M.nnames++];
                memset(n, 0, sizeof *n);
                snprintf(n->name, sizeof n->name, "%s", l->name);
                n->st = NS_OWNED;
                n->expiry = M.now + 365LL * 86400;
                n->bytes_left = ZONE_BUDGET;
            }
            M.balance -= (mine ? burn : l->price) + 2 * UI_FEE_K;
            for (int i = UI.listing_target; i < M.nlist - 1; i++) M.listings[i] = M.listings[i + 1];
            M.nlist--;
        }
        close_dlg();
    }
}

// ── reserved → settle (3e) ───────────────────────────────────────────────────
static void d_settle(struct nk_context *ctx, struct nk_rect screen) {
    if (UI.listing_target < 0 || UI.listing_target >= M.nlist) { close_dlg(); return; }
    Listing *l = &M.listings[UI.listing_target];
    int mine = l->is_mine;                        // completing a §3.7 self-reclaim
    int64_t dep = 2 * dep_leg(l->price), rem = l->price - dep;
    const char *why;
    if (l->reserve_end <= M.now) why = TR(S_DLG_SETTLE_WHY_EXPIRED);
    else if (l->pending) why = TR(S_DLG_WHY_QUEUED);
    // §5: the remainder output must clear dust or the settle can't relay
    else if (rem < UI_DUST_K) why = TR(S_DLG_SETTLE_WHY_DUST);
    else why = why_pay(rem + UI_FEE_K);           // must fund the remainder (returns, when mine)

    float w = 344, pad = 18, cw = w - 2 * pad;
    float h = pad + 30 + 34 + 8 + 4 * 18 + 12 + 26 + why_h(why) + 12 + 38 + pad;
    struct nk_rect r = dlg_begin(ctx, screen, w, h, C_BORDER);
    float x = r.x + pad, xr = r.x + w - pad, y = r.y + pad;
    char b[64];

    dlg_title(ctx, x, y, mine ? TR(S_DLG_TITLE_RECLAIM) : TR(S_DLG_TITLE_BUY), l->name, C_TEXT, C_ACCENT);
    dk_badge(ctx, xr - dk_badge_w(TR(S_DLG_SETTLE_BADGE)), y + 4, TR(S_DLG_SETTLE_BADGE), BADGE_LINE_ACCENT);
    y += 34;
    fmt_hms(b, sizeof b, l->reserve_end - M.now);
    dk_text(ctx, F_SM26, x, y, C_ACCENT, b);
    dk_text(ctx, F_PH12, x + dk_w(F_SM26, b) + 10, y + 10, C_DIM,
            mine ? TR(S_DLG_SETTLE_TIMER_MINE) : TR(S_DLG_TIMER_BUY));
    y += 40;
    fmt_amount_sp(b, sizeof b, l->price);
    ui_kv_row(ctx, x, xr, y, TR(S_DLG_LIST_PRICE), b, C_DIM, C_TEXT);
    y += 18;
    fmt_amount_sp(b, sizeof b, dep);
    char db[64];
    snprintf(db, sizeof db, "%s \xE2\x9C\x93", b);
    ui_kv_row(ctx, x, xr, y, TR(S_DLG_SETTLE_PAID), db, C_DIM, C_GREEN);   // ASCII minus: U+2212 not in the atlas
    y += 18;
    fmt_amount_sp(b, sizeof b, rem);
    ui_kv_row(ctx, x, xr, y, mine ? TR(S_DLG_SETTLE_REM_MINE) : TR(S_DLG_SETTLE_REM),
              b, C_DIM, mine ? C_GREEN : C_TEXT);
    y += 18;
    fee_total(ctx, x, xr, &y, UI_FEE_K, (mine ? 0 : rem) + UI_FEE_K, C_ACCENT);

    float by = r.y + h - pad - 38;
    why_line(ctx, x, by, why);
    int act = dlg_pair_gated(ctx, x, by, cw, TR(S_CANCEL), mine ? TR(S_DLG_SETTLE_OK_MINE) : TR(S_DLG_BUY_OK),
                             BTN_GREEN, 1.4f, why);
    if (act == 1) close_dlg();
    if (act == 2 && !why) {
        if (!M.demo) {
            ops_settle(l->name);        // the name conveys when the block folds
        } else {
            int ex = -1;                // a reclaim settles a name we already hold
            for (int i = 0; i < M.nnames; i++)
                if (!strcmp(M.names[i].name, l->name)) { ex = i; break; }
            if (ex >= 0) {
                M.names[ex].st = NS_OWNED;          // out of escrow, back to plain owned
                M.names[ex].list_price = 0;
                M.names[ex].list_window_end = 0;
            } else if (M.nnames < 16) {
                MyName *n = &M.names[M.nnames++];
                memset(n, 0, sizeof *n);
                snprintf(n->name, sizeof n->name, "%s", l->name);
                n->st = NS_OWNED;
                n->expiry = M.now + 365LL * 86400;   // the lease conveys; demo: fresh year
                n->bytes_left = ZONE_BUDGET;
            }
            M.balance -= (mine ? 0 : rem) + UI_FEE_K;   // mine: the remainder pays back to self
            for (int i = UI.listing_target; i < M.nlist - 1; i++) M.listings[i] = M.listings[i + 1];
            M.nlist--;
        }
        close_dlg();
    }
}

// ── blocked double-reserve (3e) ──────────────────────────────────────────────
static void d_blocked(struct nk_context *ctx, struct nk_rect screen) {
    if (UI.listing_target < 0 || UI.listing_target >= M.nlist) { close_dlg(); return; }
    Listing *l = &M.listings[UI.listing_target];
    float w = 344, pad = 18, cw = w - 2 * pad;
    char left[24];
    fmt_days_left(left, sizeof left, l->reserve_end - M.now);
    char body[128], note[160];
    snprintf(body, sizeof body, TR(S_DLG_BLOCKED_BODY_FMT), left);
    snprintf(note, sizeof note, TR(S_DLG_BLOCKED_NOTE_FMT), left);
    float body_h = dk_wrap(NULL, F_PH14, 0, 0, cw, C_DIM, body, 1.35f);
    float note_h = dk_wrap(NULL, F_SM10, 0, 0, cw - 22, C_GHOST, note, 1.5f);
    float h = pad + 30 + 8 + body_h + 10 + note_h + 20 + 12 + 38 + pad;
    struct nk_rect r = dlg_begin(ctx, screen, w, h, C_RED);
    float x = r.x + pad, y = r.y + pad;

    dlg_title(ctx, x, y, TR(S_DLG_BLOCKED_TITLE), l->name, C_RED, C_RED);
    y += 36;
    y = dk_wrap(ctx, F_PH14, x, y, cw, C_DIM, body, 1.35f) + 10;
    struct nk_rect nb = nk_rect(x, y, cw, note_h + 18);
    dk_card(ctx, nb, 7, C_INPUT, C_BORDER);
    dk_wrap(ctx, F_SM10, x + 11, y + 9, cw - 22, C_GHOST, note, 1.5f);

    int act = dlg_pair(ctx, x, r.y + h - pad - 38, cw, TR(S_CANCEL), TR(S_DLG_BLOCKED_OK),
                       BTN_LINE_FILL, 1.4f);
    if (act) close_dlg();
}

// ── pay an offer-to-me (3f) ──────────────────────────────────────────────────
static void d_payoffer(struct nk_context *ctx, struct nk_rect screen) {
    if (UI.offer_target < 0 || UI.offer_target >= M.noffers) { close_dlg(); return; }
    OfferToMe *o = &M.offers[UI.offer_target];
    const char *why;
    if (o->expires <= M.now) why = TR(S_DLG_PAYOFFER_WHY_CLOSED);
    else if (o->pending) why = TR(S_DLG_WHY_QUEUED);
    // §5: PAY's full-price output must clear dust or the tx can't relay
    else if (o->price < UI_DUST_K) why = TR(S_DLG_PAYOFFER_WHY_DUST);
    else why = why_pay(o->price + UI_FEE_K);
    float w = 344, pad = 18, cw = w - 2 * pad;
    float body_h = dk_wrap(NULL, F_PH14, 0, 0, cw, C_DIM,
        TR(S_DLG_PAYOFFER_BODY), 1.35f);
    float h = pad + 30 + 6 + body_h + 8 + 30 + 12 + 2 * 18 + 12 + 26
            + why_h(why) + 12 + 38 + pad - 18;
    struct nk_rect r = dlg_begin(ctx, screen, w, h, C_GREEN);
    float x = r.x + pad, xr = r.x + w - pad, y = r.y + pad;
    char b[64];

    dlg_title(ctx, x, y, TR(S_DLG_TITLE_BUY), o->name, C_TEXT, C_ACCENT);
    dk_badge(ctx, xr - dk_badge_w(TR(S_DLG_PAYOFFER_BADGE)), y + 4, TR(S_DLG_PAYOFFER_BADGE), BADGE_LINE_GREEN);
    y += 32;
    y = dk_wrap(ctx, F_PH14, x, y, cw, C_DIM,
        TR(S_DLG_PAYOFFER_BODY),
        1.35f) + 6;
    fmt_hms(b, sizeof b, o->expires - M.now);
    dk_text(ctx, F_SM22, x, y, C_ACCENT, b);
    dk_text(ctx, F_PH12, x + dk_w(F_SM22, b) + 10, y + 8, C_DIM, TR(S_DLG_TIMER_BUY));
    y += 36;
    dk_hline(ctx, x, xr, y, C_BORDER);
    y += 10;
    fmt_amount_sp(b, sizeof b, o->price);
    ui_kv_row(ctx, x, xr, y, TR(S_DLG_PRICE), b, C_DIM, C_TEXT);
    y += 18;
    fee_total(ctx, x, xr, &y, UI_FEE_K, o->price + UI_FEE_K, C_ACCENT);

    float by = r.y + h - pad - 38;
    why_line(ctx, x, by, why);
    int act = dlg_pair_gated(ctx, x, by, cw, TR(S_CANCEL), TR(S_DLG_BUY_OK), BTN_GREEN, 1.4f, why);
    if (act == 1) close_dlg();
    if (act == 2 && !why) {
        if (!M.demo) {
            ops_payoffer(o->name);
        } else {
            if (M.nnames < 16) {
                MyName *n = &M.names[M.nnames++];
                memset(n, 0, sizeof *n);
                snprintf(n->name, sizeof n->name, "%s", o->name);
                n->st = NS_OWNED;
                n->expiry = M.now + 365LL * 86400;
                n->bytes_left = ZONE_BUDGET;
            }
            M.balance -= o->price + UI_FEE_K;
            for (int i = UI.offer_target; i < M.noffers - 1; i++) M.offers[i] = M.offers[i + 1];
            M.noffers--;
        }
        close_dlg();
    }
}


// ═════════════════ DNS record modal (9f add / 9g edit) ══════════════════════
// One modal, two moods: add starts blank; edit arrives pre-filled and carries
// Delete (publish an empty record — the log's delete convention) bottom-left.
// Edit = overwrite; if the host or type changed, the original record is
// deleted first so "edit" never silently forks a second record.

static const struct { const char *n; int code; } DNSM_TYPES[] = {
    { "A", DNS_A }, { "AAAA", DNS_AAAA }, { "CNAME", DNS_CNAME },
    { "TXT", DNS_TXT }, { "MX", DNS_MX },
    // under "more…"
    { "SRV", DNS_SRV }, { "NS", DNS_NS }, { "SSHFP", DNS_SSHFP },
    { "OPENPGPKEY", DNS_OPENPGPKEY },
};
#define DNSM_N        ((int)(sizeof DNSM_TYPES / sizeof DNSM_TYPES[0]))
#define DNSM_PRIMARY  5

int ui_dnsm_type_from_code(int code) {
    for (int i = 0; i < DNSM_N; i++)
        if (DNSM_TYPES[i].code == code) return i;
    return 0;
}

static const char *dnsm_err_for(int code) {
    switch (code) {
        case DNS_A:     return TR(S_DLG_DNSREC_ERR_A);
        case DNS_AAAA:  return TR(S_DLG_DNSREC_ERR_AAAA);
        case DNS_CNAME:
        case DNS_NS:    return TR(S_DLG_DNSREC_ERR_HOST);
        case DNS_MX:    return TR(S_DLG_DNSREC_ERR_MX);
        case DNS_TXT:   return TR(S_DLG_DNSREC_ERR_TXT);
        case DNS_SRV:   return TR(S_DLG_DNSREC_ERR_SRV);
        case DNS_SSHFP: return TR(S_DLG_DNSREC_ERR_SSHFP);
        default:        return TR(S_DLG_DNSREC_ERR_HEX);
    }
}

static int dnsm_host_ok(const char *h) {
    if (!h[0] || !strcmp(h, "@")) return 1;
    for (const char *p = h; *p; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') ||
              *p == '-' || *p == '_' || *p == '.'))
            return 0;
    return 1;
}

static void d_dns_rec(struct nk_context *ctx, struct nk_rect screen) {
    int ni = ui_dns_pick_name();
    if (ni < 0) { close_dlg(); return; }
    const char *apex = M.names[ni].name;

    UI.dnsm_host[UI.dnsm_host_len] = 0;
    UI.dnsm_ttl[UI.dnsm_ttl_len] = 0;
    UI.dnsm_val[UI.dnsm_val_len] = 0;

    int tsel = UI.dnsm_type_sel;
    if (tsel < 0 || tsel >= DNSM_N) tsel = UI.dnsm_type_sel = 0;
    int tcode = DNSM_TYPES[tsel].code;
    int ntypes = UI.dnsm_more ? DNSM_N : DNSM_PRIMARY;

    // validate: host charset, ttl digits, value through the REAL parser
    const char *label = (!UI.dnsm_host_len || !strcmp(UI.dnsm_host, "@"))
                        ? "@" : UI.dnsm_host;
    int host_ok = dnsm_host_ok(UI.dnsm_host);
    uint32_t ttlv = (uint32_t)atoi(UI.dnsm_ttl_len ? UI.dnsm_ttl : "0");
    int ttl_ok = ttlv > 0;
    zone_rec rec;
    int val_ok = UI.dnsm_val_len > 0 && host_ok &&
                 zone_build_rec(label, DNSM_TYPES[tsel].n, ttlv ? ttlv : 3600,
                                UI.dnsm_val, &rec) == 0 && rec.rdlen > 0;
    int can = val_ok && ttl_ok && !M.demo;

    // record wire estimate: label + type/ttl/len overhead + rdata
    int est = val_ok ? (int)strlen(rec.label) + 12 + rec.rdlen : 0;

    // type chip rows flow — measure height first
    float w = 520, pad = 18, cw = w - 2 * pad;
    float chiprows_h = 0;
    {
        float cx = 0;
        int rows = 1;
        for (int i = 0; i < ntypes + (UI.dnsm_more ? 0 : 1); i++) {
            const char *nm = i < ntypes ? DNSM_TYPES[i].n : TR(S_DLG_DNSREC_MORE);
            float bw2 = dk_w(F_SMB10, nm) + 28;
            if (cx + bw2 > cw) { rows++; cx = 0; }
            cx += bw2 + 6;
        }
        chiprows_h = rows * 32.0f;
    }
    int val_err = UI.dnsm_val_len > 0 && !val_ok;
    float h = pad + 34                       // title
            + 16 + chiprows_h                // TYPE
            + 16 + 22 + 34                   // HOST/TTL labels + fields
            + 16 + 22 + 34 + (val_err ? 16 : 0)   // VALUE (+error line)
            + 10 + 40 + 18                   // PREVIEW + byte line
            + 12 + 38 + pad;                 // buttons
    struct nk_rect r = dlg_begin(ctx, screen, w, h, C_BORDER);
    float x = r.x + pad, xr = r.x + w - pad, y = r.y + pad;
    char b[160];

    dlg_title(ctx, x, y, UI.dnsm_edit ? TR(S_DLG_DNSREC_TITLE_EDIT) : TR(S_DLG_DNSREC_TITLE_ADD), NULL,
              C_TEXT, C_TEXT);
    {
        char nm[80];
        snprintf(nm, sizeof nm, "%s" APP_DOT_TLD, apex);
        dk_text(ctx, F_SM11, x + dk_w(F_PH22, UI.dnsm_edit ? TR(S_DLG_DNSREC_TITLE_EDIT)
                                                           : TR(S_DLG_DNSREC_TITLE_ADD)) + 10,
                y + 8, C_GHOST, nm);
    }
    struct nk_rect xb = nk_rect(xr - 22, y, 22, 22);
    dk_text_c(ctx, F_SM16, xb, dk_hot(ctx, xb) ? C_DIM : C_GHOST, "\xE2\x9C\x95");
    if (dk_click(ctx, xb)) { close_dlg(); return; }
    y += 34;

    // TYPE chips
    dk_text_sp(ctx, F_SM9, x, y, C_GHOST, TR(S_COL_TYPE), 1);
    y += 16;
    {
        float cx = x;
        for (int i = 0; i < ntypes; i++) {
            float bw2 = dk_w(F_SMB10, DNSM_TYPES[i].n) + 28;
            if (cx + bw2 > xr) { cx = x; y += 32; }
            struct nk_rect tc = nk_rect(cx, y, bw2, 26);
            int selc = i == tsel;
            if (selc) {
                dk_fill(ctx, tc, 6, C_ACCENT);
                dk_text_c(ctx, F_SMB10, tc, C_ONFILL, DNSM_TYPES[i].n);
            } else {
                dk_card(ctx, tc, 6, C_INPUT, C_BORDER);
                dk_text_c(ctx, F_SMB10, tc, C_TEXT, DNSM_TYPES[i].n);
            }
            if (dk_hot(ctx, tc)) sapp_set_mouse_cursor(SAPP_MOUSECURSOR_POINTING_HAND);
            if (dk_click(ctx, tc)) UI.dnsm_type_sel = i;
            cx += bw2 + 6;
        }
        if (!UI.dnsm_more) {
            float bw2 = dk_w(F_SMB10, TR(S_DLG_DNSREC_MORE)) + 24;
            if (cx + bw2 > xr) { cx = x; y += 32; }
            struct nk_rect mc = nk_rect(cx, y, bw2, 26);
            dk_rect_dashed(ctx, mc, 6, HEXC(0x464A38));
            dk_text_c(ctx, F_SM11, mc, C_DIM, TR(S_DLG_DNSREC_MORE));
            if (dk_hot(ctx, mc)) sapp_set_mouse_cursor(SAPP_MOUSECURSOR_POINTING_HAND);
            if (dk_click(ctx, mc)) UI.dnsm_more = 1;
        }
        y += 32;
    }
    y += 16;

    // HOST + TTL
    dk_text_sp(ctx, F_SM9, x, y, C_GHOST, TR(S_COL_HOST), 1);
    dk_text_sp(ctx, F_SM9, xr - 130, y, C_GHOST, TR(S_COL_TTL), 1);
    y += 16;
    {
        struct nk_rect hf = nk_rect(x, y, cw - 142, 30);
        dk_card(ctx, hf, 8, C_INPUT, host_ok ? C_BORDER : C_RED);
        ui_edit(ctx, nk_rect(hf.x + 6, hf.y + 2, hf.w - 12, 26), UI.dnsm_host,
                &UI.dnsm_host_len, sizeof UI.dnsm_host - 1, TR(S_DLG_DNSREC_HOST_PH),
                F_SM13, 1);
        struct nk_rect tf = nk_rect(xr - 130, y, 130, 30);
        dk_card(ctx, tf, 8, C_INPUT, ttl_ok || !UI.dnsm_ttl_len ? C_BORDER : C_RED);
        ui_edit(ctx, nk_rect(tf.x + 6, tf.y + 2, tf.w - 12, 26), UI.dnsm_ttl,
                &UI.dnsm_ttl_len, sizeof UI.dnsm_ttl - 1, "3600", F_SM13, 1);
        y += 34 + 16;
    }

    // VALUE + inline error
    dk_text_sp(ctx, F_SM9, x, y, C_GHOST, TR(S_COL_VALUE), 1);
    y += 16;
    {
        struct nk_rect vf = nk_rect(x, y, cw, 30);
        dk_card(ctx, vf, 8, C_INPUT, val_err ? C_RED : C_BORDER);
        ui_edit(ctx, nk_rect(vf.x + 6, vf.y + 2, vf.w - 12 - 18, 26), UI.dnsm_val,
                &UI.dnsm_val_len, sizeof UI.dnsm_val - 1,
                tcode == DNS_A ? "203.0.113.10"
                : tcode == DNS_TXT ? TR(S_DLG_DNSREC_TXT_PH) : TR(S_DLG_DNSREC_VAL_PH), F_SM13, 1);
        if (val_err)
            dk_text_r(ctx, F_SM13, vf.x + vf.w - 10, y + 7, C_RED, "\xE2\x9C\x95");
        y += 34;
        if (val_err) {
            dk_text(ctx, F_SM10, x, y - 2, C_RED, dnsm_err_for(tcode));
            y += 16;
        }
    }
    y += 10;

    // PREVIEW dry-run row + byte estimate
    {
        struct nk_rect pv = nk_rect(x, y, cw, 34);
        dk_card(ctx, pv, 8, C_BG, C_BORDER);
        dk_text_sp(ctx, F_SM9, pv.x + 12, y + 11, C_GHOST, TR(S_DLG_DNSREC_PREVIEW), 1);
        char fq[128];
        if (!strcmp(label, "@"))
            snprintf(fq, sizeof fq, "%s" APP_DOT_TLD, apex);
        else
            snprintf(fq, sizeof fq, "%s.%s" APP_DOT_TLD, label, apex);
        float px = pv.x + 82;
        dk_text(ctx, F_SM11, px, y + 10, val_ok ? C_GREEN : C_FADE3, fq);
        px += dk_w(F_SM11, fq) + 10;
        dk_text(ctx, F_SM11, px, y + 10, C_GHOST, DNSM_TYPES[tsel].n);
        px += dk_w(F_SM11, DNSM_TYPES[tsel].n) + 10;
        if (val_ok) {
            char disp[120];
            ui_rdata_str(&rec, disp, sizeof disp);
            snprintf(b, sizeof b, "\xE2\x86\x92 %s", disp);
        } else {
            snprintf(b, sizeof b, "\xE2\x86\x92 \xE2\x80\x94");
        }
        dk_clip_push(ctx, nk_rect(px, y, pv.x + pv.w - px - 8, 34));
        dk_text(ctx, F_SM11, px, y + 10, val_ok ? C_DIM : C_FADE3, b);
        dk_clip_pop(ctx);
        y += 40;
        if (val_ok && est > 80)
            snprintf(b, sizeof b,
                     TR(S_DLG_DNSREC_BYTES_OVER_FMT), est);
        else if (val_ok)
            snprintf(b, sizeof b, TR(S_DLG_DNSREC_BYTES_FMT), est);
        else
            b[0] = 0;
        if (b[0]) dk_text(ctx, F_SM10, x, y - 2, C_GHOST, b);
        y += 18;
    }
    y += 12;

    // buttons: [Delete]  ·  Cancel / Add|Save
    float by = r.y + h - pad - 38;
    if (UI.dnsm_edit) {
        float dw = dk_w(F_PH16, TR(S_DLG_DNSREC_DELETE)) + 34;
        struct nk_rect db = nk_rect(x, by, dw, 38);
        dk_card(ctx, db, 8, C_TINT_RED, C_TINT_RED_BR);
        dk_text_c(ctx, F_PH16, db, C_RED, TR(S_DLG_DNSREC_DELETE));
        if (dk_hot(ctx, db)) sapp_set_mouse_cursor(SAPP_MOUSECURSOR_POINTING_HAND);
        if (dk_click(ctx, db)) {
            zone_rec del;
            memset(&del, 0, sizeof del);
            snprintf(del.label, sizeof del.label, "%s", UI.dnsm_orig_label);
            del.type = (uint16_t)UI.dnsm_orig_type;
            del.ttl = 0;
            del.rdlen = 0;                       // empty PUT = delete
            dnsnet_publish(apex, &del);
            dirscan_kick();
            close_dlg();
            return;
        }
    }
    {
        float ow = dk_w(F_PH16, UI.dnsm_edit ? TR(S_DLG_DNSREC_SAVE) : TR(S_DLG_DNSREC_ADD)) + 40;
        float cw2 = dk_w(F_PH16, TR(S_DLG_CANCEL)) + 36;
        struct nk_rect cb = nk_rect(xr - ow - 8 - cw2, by, cw2, 38);
        struct nk_rect ob = nk_rect(xr - ow, by, ow, 38);
        if (dk_btn_col(ctx, cb, F_PH16, TR(S_DLG_CANCEL), BTN_LINE_FILL, C_DIM))
            { close_dlg(); return; }
        if (can) {
            if (dk_btn(ctx, ob, F_PH16, UI.dnsm_edit ? TR(S_DLG_DNSREC_SAVE) : TR(S_DLG_DNSREC_ADD),
                       BTN_ACCENT)) {
                // edit that re-keys (host/type changed) deletes the original
                if (UI.dnsm_edit &&
                    (strcmp(rec.label, UI.dnsm_orig_label) != 0 ||
                     rec.type != (uint16_t)UI.dnsm_orig_type)) {
                    zone_rec del;
                    memset(&del, 0, sizeof del);
                    snprintf(del.label, sizeof del.label, "%s", UI.dnsm_orig_label);
                    del.type = (uint16_t)UI.dnsm_orig_type;
                    del.rdlen = 0;
                    dnsnet_publish(apex, &del);
                }
                dnsnet_publish(apex, &rec);
                // auto-pin (design note): a fresh host must not fail
                // invisibly — if no TLSA covers this host yet and a cert
                // does (its own, else the apex wildcard), publish its pin
                // alongside the address record.
                if (rec.type == DNS_A || rec.type == DNS_AAAA ||
                    rec.type == DNS_CNAME) {
                    char tl[96];
                    if (rec.label[0])
                        snprintf(tl, sizeof tl, "_443._tcp.%s", rec.label);
                    else
                        snprintf(tl, sizeof tl, "_443._tcp");
                    zone zc;
                    int nz = dnsnet_zone(apex, &zc), have = 0;
                    for (int i = 0; i < nz; i++)
                        if (zc.recs[i].type == DNS_TLSA &&
                            !strcmp(zc.recs[i].label, tl))
                            have = 1;
                    uint8_t spki[32];
                    char host[144];
                    if (rec.label[0])
                        snprintf(host, sizeof host, "%s.%s", rec.label, apex);
                    else
                        snprintf(host, sizeof host, "%s", apex);
                    if (!have && (webproxy_origin_probe(host, spki) ||
                                  webproxy_origin_probe(apex, spki))) {
                        char rd[80];
                        size_t o2 = (size_t)snprintf(rd, sizeof rd, "3 1 1 ");
                        for (int i = 0; i < 32; i++)
                            o2 += (size_t)snprintf(rd + o2, sizeof rd - o2,
                                                   "%02x", spki[i]);
                        zone_rec pin;
                        if (zone_build_rec(tl, "TLSA", 3600, rd, &pin) == 0)
                            dnsnet_publish(apex, &pin);
                    }
                }
                dirscan_kick();
                close_dlg();
                return;
            }
        } else {
            ui_btn_disabled(ctx, ob, F_PH16, UI.dnsm_edit ? TR(S_DLG_DNSREC_SAVE) : TR(S_DLG_DNSREC_ADD));
        }
    }
}

// ═════════════════ subdomain certificate (9d "+ certificate…") ═══════════════
static void d_ssl_sub(struct nk_context *ctx, struct nk_rect screen) {
    int ni = ui_dns_pick_name();
    if (ni < 0) { close_dlg(); return; }
    const char *apex = M.names[ni].name;
    UI.ssl_sub[UI.ssl_sub_len] = 0;

    int sub_ok = UI.ssl_sub_len > 0;
    for (const char *p = UI.ssl_sub; sub_ok && *p; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') ||
              *p == '-' || *p == '.'))
            sub_ok = 0;

    float w = 430, pad = 18, cw = w - 2 * pad;
    float h = pad + 34 + 40 + 16 + 34 + 26 + 44 + 12 + 38 + pad;
    struct nk_rect r = dlg_begin(ctx, screen, w, h, C_BORDER);
    float x = r.x + pad, xr = r.x + w - pad, y = r.y + pad;
    char b[160];

    dlg_title(ctx, x, y, TR(S_DLG_SSLSUB_TITLE), NULL, C_TEXT, C_TEXT);
    y += 34;
    dk_wrap(ctx, F_PH12, x, y, cw, C_DIM,
            TR(S_DLG_SSLSUB_BODY), 1.3f);
    y += 40;
    dk_text_sp(ctx, F_SM9, x, y, C_GHOST, TR(S_DLG_SSLSUB_LABEL), 1);
    y += 16;
    {
        struct nk_rect sf = nk_rect(x, y, cw, 30);
        dk_card(ctx, sf, 8, C_INPUT, UI.ssl_sub_len && !sub_ok ? C_RED : C_BORDER);
        ui_edit(ctx, nk_rect(sf.x + 6, sf.y + 2, sf.w / 2, 26), UI.ssl_sub,
                &UI.ssl_sub_len, sizeof UI.ssl_sub - 1, TR(S_DLG_SSLSUB_PH), F_SM13, 1);
        snprintf(b, sizeof b, ".%s" APP_DOT_TLD, apex);
        dk_text_r(ctx, F_SM13, sf.x + sf.w - 10, y + 8, C_GHOST, b);
        y += 34;
    }
    if (UI.ssl_sub_len && !sub_ok) {
        dk_text(ctx, F_SM10, x, y, C_RED, TR(S_DLG_SSLSUB_ERR));
    }
    y += 26;
    {
        struct nk_rect note = nk_rect(x, y, cw, 38);
        dk_card(ctx, note, 8, C_TINT_OK, C_TINT_OK_BR);
        char lb[96];
        snprintf(lb, sizeof lb, TR(S_DLG_SSLSUB_NOTE_FMT),
                 sub_ok ? UI.ssl_sub : TR(S_DLG_SSLSUB_TOKEN));
        dk_clip_push(ctx, note);
        dk_text(ctx, F_PH12, note.x + 12, y + 9, C_DIM, lb);
        dk_clip_pop(ctx);
        y += 44;
    }

    float by = r.y + h - pad - 38;
    int act = dlg_pair_gated(ctx, x, by, cw, TR(S_DLG_CANCEL), TR(S_DLG_SSLSUB_OK), BTN_ACCENT, 1.2f,
                             sub_ok && !M.demo ? NULL : "");
    if (act == 1) close_dlg();
    if (act == 2 && sub_ok && !M.demo) {
        char host[112];
        snprintf(host, sizeof host, "%s.%s", UI.ssl_sub, apex);
        uint8_t spki[32]; int created = 0;
        if (webproxy_origin_ensure(host, 1, spki, &created)) {
            char lbl[80], rdata[80];
            snprintf(lbl, sizeof lbl, "_443._tcp.%s", UI.ssl_sub);
            size_t o = (size_t)snprintf(rdata, sizeof rdata, "3 1 1 ");
            for (int i = 0; i < 32; i++)
                o += (size_t)snprintf(rdata + o, sizeof rdata - o, "%02x", spki[i]);
            zone_rec rec;
            if (zone_build_rec(lbl, "TLSA", 3600, rdata, &rec) == 0) {
                dnsnet_publish(apex, &rec);
                dirscan_kick();
            }
            ui_ssl_dirty();
        }
        close_dlg();
    }
}

// ═════════════════ delete certificate (destructive confirm) ═════════════════
static void d_ssl_del(struct nk_context *ctx, struct nk_rect screen) {
    if (!UI.ssl_del_host[0]) { close_dlg(); return; }
    float w = 400, pad = 18, cw = w - 2 * pad;
    float body_h = dk_wrap(NULL, F_PH14, 0, 0, cw, C_DIM,
                           TR(S_DLG_SSLDEL_BODY), 1.35f);
    float h = pad + 34 + body_h + 12 + 24 + 16 + 38 + pad;
    struct nk_rect r = dlg_begin(ctx, screen, w, h, C_RED);
    float x = r.x + pad, y = r.y + pad;
    char b[112];

    dk_text(ctx, F_PH22, x, y, C_RED, TR(S_DLG_SSLDEL_TITLE));
    snprintf(b, sizeof b, "%s" APP_DOT_TLD, UI.ssl_del_host);
    dk_text(ctx, F_SM16, x + dk_w(F_PH22, TR(S_DLG_SSLDEL_TITLE)) + 8, y + 5,
            C_RED, b);
    y += 34;
    y = dk_wrap(ctx, F_PH14, x, y, cw, C_DIM, TR(S_DLG_SSLDEL_BODY), 1.35f) + 12;

    // keep-pin choice (checked = pin comes down with the cert; default on)
    {
        struct nk_rect cbx = nk_rect(x, y + 2, 15, 15);
        if (UI.ssl_del_keep_pin) dk_line_rect(ctx, cbx, 4, C_GHOST);
        else {
            dk_fill(ctx, cbx, 4, C_RED);
            dk_text_c(ctx, F_SM9, cbx, C_ONFILL, "\xE2\x9C\x93");
        }
        dk_text(ctx, F_PH12, cbx.x + 22, y + 2, C_DIM, TR(S_DLG_SSLDEL_UNPIN));
        struct nk_rect hit = nk_rect(x, y, 22 + dk_w(F_PH12, TR(S_DLG_SSLDEL_UNPIN)), 19);
        if (dk_click(ctx, hit)) UI.ssl_del_keep_pin = !UI.ssl_del_keep_pin;
        y += 24;
    }

    float by = r.y + h - pad - 38;
    int act = dlg_pair(ctx, x, by, cw, TR(S_DLG_CANCEL), TR(S_DLG_SSLDEL_OK), BTN_RED, 1.0f);
    if (act == 1) close_dlg();
    if (act == 2) {
        if (!M.demo) {
            webproxy_origin_delete(UI.ssl_del_host);
            if (!UI.ssl_del_keep_pin) dnsnet_unpublish_tlsa(UI.ssl_del_host);
            ui_ssl_dirty();
            dirscan_kick();
        }
        close_dlg();
    }
}

// ═════════════════ first-run consent (9h) ════════════════════════════════════
// One admin prompt, scoped promise, honest skip path. Shows once (the marker
// file records the answer); Settings keeps the enable/uninstall pair after.
static void d_consent(struct nk_context *ctx, struct nk_rect screen) {
    float w = 470, pad = 26;
    float h = 24 + 34 + 14 + 46 + 16 + 3 * 40 + 18 + 44 + 22;
    struct nk_rect r = dlg_begin(ctx, screen, w, h, HEXC(0x464A38));
    float x = r.x + pad, xr = r.x + w - pad, y = r.y + 24;
    float cw = xr - x;

    dk_text(ctx, F_PH22, x, y, C_TEXT, TR(S_DLG_CONSENT_TITLE));
    y += 34 + 14;

    // scope promise strip
    {
        struct nk_rect sp = nk_rect(x, y, cw, 40);
        dk_card(ctx, sp, 10, C_TINT_OK, C_TINT_OK_BR);
        dk_text(ctx, F_SM13, sp.x + 12, y + 11, C_GREEN, "\xE2\x9C\x93");
        dk_clip_push(ctx, sp);
        dk_text(ctx, F_PH14, sp.x + 32, y + 9, HEXC(0xCDD7AD),
                TR(S_DLG_CONSENT_PROMISE));
        dk_clip_pop(ctx);
        y += 46 + 16;
    }

    const struct { const char *num, *title, *sub; } STEPS[3] = {
        { "01", TR(S_DLG_CONSENT_S1), TR(S_DLG_CONSENT_S1_SUB) },
        { "02", TR(S_DLG_CONSENT_S2), TR(S_DLG_CONSENT_S2_SUB) },
        { "03", TR(S_DLG_CONSENT_S3), TR(S_DLG_CONSENT_S3_SUB) },
    };
    for (int i = 0; i < 3; i++) {
        dk_text(ctx, F_SM13, x, y + 1, C_ACCENT, STEPS[i].num);
        dk_text(ctx, F_PH14, x + 30, y - 1, C_TEXT, STEPS[i].title);
        dk_text(ctx, F_SM10, x + 30, y + 19, C_GHOST, STEPS[i].sub);
        y += 40;
    }
    y += 18;

    // footer: skip (honest) · enable (the one prompt)
    {
        struct nk_rect sk = nk_rect(x, y, 130, 40);
        int hot = dk_hot(ctx, sk);
        dk_text(ctx, F_PH14, x, y, hot ? C_TEXT : C_DIM, TR(S_DLG_CONSENT_SKIP));
        dk_text(ctx, F_SM9, x, y + 21, C_GHOST, TR(S_DLG_CONSENT_SKIP_SUB));
        if (hot) sapp_set_mouse_cursor(SAPP_MOUSECURSOR_POINTING_HAND);
        if (dk_click(ctx, sk)) {
            sysinstall_consent_mark();
            close_dlg();
            return;
        }
        float ew = dk_w(F_PH16, TR(S_DLG_CONSENT_ENABLE)) + 44;
        struct nk_rect eb = nk_rect(xr - ew, y - 2, ew, 40);
        if (dk_btn(ctx, eb, F_PH16, TR(S_DLG_CONSENT_ENABLE), BTN_ACCENT)) {
            int ok = M.demo ? 0 : sysinstall_install();
            sysinstall_consent_mark();
            snprintf(UI.web_note, sizeof UI.web_note, "%s",
                     ok ? TR(S_DLG_CONSENT_ENABLED) : TR(S_DLG_CONSENT_INCOMPLETE));
            UI.web_busy = 240;
            close_dlg();
            return;
        }
    }
}

// ═════════════════ single-writer lock (Retry / Quit) ════════════════════════
// Another desktop holds <coin>.db.lock — engines are parked. Retry re-tries
// the flock and boots everything on success; Quit exits (nothing started).
int  app_db_locked(void);            // main.c seam
int  app_db_retry(void);

static void d_locked(struct nk_context *ctx, struct nk_rect screen) {
    if (!app_db_locked()) { close_dlg(); return; }     // resolved elsewhere
    float w = 430, pad = 22;
    float h = pad + 34 + 64 + 16 + 38 + pad;
    struct nk_rect r = dlg_begin(ctx, screen, w, h, C_TINT_RED_BR);
    float x = r.x + pad, y = r.y + pad;
    float cw = w - 2 * pad;

    dlg_title(ctx, x, y, TR(S_DLG_LOCKED_TITLE), NULL, C_TEXT, C_TEXT);
    y += 34;
    dk_wrap(ctx, F_PH14, x, y, cw, C_DIM,
            TR(S_DLG_LOCKED_BODY), 1.3f);
    y += 64 + 16;

    float bw = (cw - 8) / 2;
    if (dk_btn_col(ctx, nk_rect(x, y, bw, 38), F_PH16, TR(S_DLG_LOCKED_QUIT), BTN_LINE_FILL, C_RED))
        exit(0);                                    // nothing started — clean
    if (dk_btn(ctx, nk_rect(x + bw + 8, y, bw, 38), F_PH16, TR(S_DLG_LOCKED_RETRY), BTN_ACCENT)) {
        if (app_db_retry()) close_dlg();
    }
}

// first-run backup nag: a freshly-minted wallet lives nowhere but this Mac's
// keychain until its 12 words are on paper — say so before anything else.
// "Show my 12 words" hands off to DLG_REVEAL_PHRASE; "Later" just closes
// (the phrase stays reachable from Settings, and the sub-line says where).
static void d_backup(struct nk_context *ctx, struct nk_rect screen) {
    if (!wallet_has_phrase()) { close_dlg(); return; }
    float w = 470, pad = 22, cw = w - 2 * pad;
    float h = pad + 34 + 80 + 10 + 34 + 16 + 38 + 8 + 14 + pad;
    struct nk_rect r = dlg_begin(ctx, screen, w, h, C_TINT_RED_BR);
    float x = r.x + pad, y = r.y + pad;

    dlg_title(ctx, x, y, TR(S_DLG_BACKUP_TITLE), NULL, C_TEXT, C_TEXT);
    y += 34;
    dk_wrap(ctx, F_PH14, x, y, cw, C_DIM, TR(S_DLG_BACKUP_BODY), 1.3f);
    y += 80 + 10;
    dk_wrap(ctx, F_PH12, x, y, cw, C_RED, TR(S_DLG_BACKUP_HINT), 1.25f);

    float by = r.y + h - pad - 14 - 8 - 38;
    int act = dlg_pair(ctx, x, by, cw, TR(S_DLG_BACKUP_LATER),
                       TR(S_DLG_BACKUP_SHOW), BTN_ACCENT, 1.6f);
    dk_text_c(ctx, F_SM9, nk_rect(x, by + 38 + 8, cw, 14), C_GHOST,
              TR(S_DLG_BACKUP_SUB));
    if (act == 1) close_dlg();
    if (act == 2) UI.dialog = DLG_REVEAL_PHRASE;
}

// ── recovery phrase (BIP39) ──────────────────────────────────────────────────
static void d_reveal_phrase(struct nk_context *ctx, struct nk_rect screen) {
    if (!wallet_has_phrase()) { close_dlg(); return; }
    float w = 460, pad = 20, cw = w - 2 * pad;
    float h = pad + 34 + 42 + 14 + 156 + 16 + 38 + pad;
    struct nk_rect r = dlg_begin(ctx, screen, w, h, C_BORDER);
    float x = r.x + pad, y = r.y + pad;

    dlg_title(ctx, x, y, TR(S_DLG_PHRASE_TITLE), NULL, C_TEXT, C_TEXT);
    y += 34;
    dk_wrap(ctx, F_PH12, x, y, cw, C_DIM,
        TR(S_DLG_PHRASE_BODY), 1.3f);
    y += 42 + 14;

    // 12 numbered words, 3 columns × 4 rows
    char mnem[128]; snprintf(mnem, sizeof mnem, "%s", wallet_mnemonic());
    char *words[12]; int nw = 0; char *sv = NULL;
    for (char *t = strtok_r(mnem, " ", &sv); t && nw < 12; t = strtok_r(NULL, " ", &sv))
        words[nw++] = t;
    struct nk_rect grid = nk_rect(x, y, cw, 156);
    dk_card(ctx, grid, 8, C_INPUT, C_BORDER);
    float colw = cw / 3.0f, rowh = 156 / 4.0f;
    for (int i = 0; i < nw; i++) {
        char cell[40];
        snprintf(cell, sizeof cell, "%2d.  %s", i + 1, words[i]);
        dk_text(ctx, F_SM13, grid.x + 14 + (i % 3) * colw,
                grid.y + 14 + (i / 3) * rowh, C_TEXT, cell);
    }
    memset(mnem, 0, sizeof mnem);
    y += 156 + 16;

    float by = r.y + h - pad - 38;
    if (dk_btn(ctx, nk_rect(x, by, cw, 38), F_PH16, TR(S_DLG_PHRASE_DONE), BTN_ACCENT))
        close_dlg();
}

static void d_restore_phrase(struct nk_context *ctx, struct nk_rect screen) {
    // success state: a plain restart prompt + Done
    if (UI.restore_done) {
        float w = 440, pad = 22;
        float h = pad + 34 + 60 + 16 + 38 + pad;
        struct nk_rect r = dlg_begin(ctx, screen, w, h, C_TINT_OK_BR);
        float x = r.x + pad, y = r.y + pad, cw = w - 2 * pad;
        dlg_title(ctx, x, y, TR(S_DLG_RESTORE_DONE_TITLE), NULL, C_TEXT, C_TEXT);
        y += 34;
        dk_wrap(ctx, F_PH14, x, y, cw, C_DIM,
            TR(S_DLG_RESTORE_DONE_BODY), 1.3f);
        y += 60 + 16;
        if (dk_btn(ctx, nk_rect(x, y, cw, 38), F_PH16, TR(S_DLG_RESTORE_DONE_OK), BTN_ACCENT)) {
            UI.restore_done = 0;
            close_dlg();
        }
        return;
    }

    UI.restore_buf[UI.restore_len] = 0;
    uint8_t ent[16];
    int valid = UI.restore_len > 0 && bip39_entropy_from_mnemonic(UI.restore_buf, ent);

    float w = 480, pad = 20, cw = w - 2 * pad;
    float h = pad + 34 + 42 + 14 + 16 + 66 + 10 + 30 + 14 + 38 + pad;
    struct nk_rect r = dlg_begin(ctx, screen, w, h, C_BORDER);
    float x = r.x + pad, y = r.y + pad;

    dlg_title(ctx, x, y, TR(S_DLG_RESTORE_TITLE), NULL, C_TEXT, C_TEXT);
    y += 34;
    dk_wrap(ctx, F_PH12, x, y, cw, C_DIM,
        TR(S_DLG_RESTORE_BODY), 1.3f);
    y += 42 + 14;

    dk_text_sp(ctx, F_SM9, x, y, C_GHOST, TR(S_DLG_RESTORE_LABEL), 1);
    y += 16;
    struct nk_rect sf = nk_rect(x, y, cw, 66);
    dk_card(ctx, sf, 8, C_INPUT, valid ? C_TINT_OK_BR : C_BORDER);
    ui_edit(ctx, nk_rect(sf.x + 8, sf.y + 6, sf.w - 16, 54), UI.restore_buf,
            &UI.restore_len, sizeof UI.restore_buf - 1,
            TR(S_DLG_RESTORE_PH), F_SM13, 1);
    y += 66 + 10;

    int err = UI.restore_msg[0] == '!';
    const char *msg = UI.restore_msg[0]
        ? (err ? UI.restore_msg + 1 : UI.restore_msg)
        : (UI.restore_len == 0 ? TR(S_DLG_RESTORE_HINT)
           : valid ? TR(S_DLG_RESTORE_VALID)
                   : TR(S_DLG_RESTORE_INVALID));
    dk_wrap(ctx, F_PH12, x, y, cw, err ? C_RED : (valid ? C_DIM : C_GHOST), msg, 1.25f);
    y += 30 + 14;

    float by = r.y + h - pad - 38;
    int act = dlg_pair_gated(ctx, x, by, cw, TR(S_DLG_CANCEL), TR(S_DLG_RESTORE_OK), BTN_ACCENT, 1.2f,
                             valid && !M.demo ? NULL : "");
    if (act == 1) close_dlg();
    if (act == 2 && valid && !M.demo) {
        if (wallet_restore(UI.restore_buf)) {
            memset(UI.restore_buf, 0, sizeof UI.restore_buf);   // scrub the typed phrase
            UI.restore_len = 0;
            UI.restore_msg[0] = 0;
            UI.restore_done = 1;
        } else {
            snprintf(UI.restore_msg, sizeof UI.restore_msg, "!%s", TR(S_DLG_RESTORE_ERR));
        }
    }
}

void dialogs_draw(struct nk_context *ctx, struct nk_rect screen) {
    switch (UI.dialog) {
        case DLG_RENEW:       d_renew(ctx, screen); break;
        case DLG_BATCH_RENEW: d_batch_renew(ctx, screen); break;
        case DLG_SELL:        d_sell(ctx, screen); break;
        case DLG_OFFER:       d_offer(ctx, screen); break;
        case DLG_TRANSFER:    d_transfer(ctx, screen); break;
        case DLG_RELEASE:     d_release(ctx, screen); break;
        case DLG_BATCH_RELEASE: d_batch_release(ctx, screen); break;
        case DLG_BATCH_TRANSFER: d_batch_transfer(ctx, screen); break;
        case DLG_CLAIM:       d_claim(ctx, screen); break;
        case DLG_BID:         d_bid(ctx, screen); break;
        case DLG_SETTLE:      d_settle(ctx, screen); break;
        case DLG_BLOCKED:     d_blocked(ctx, screen); break;
        case DLG_PAYOFFER:    d_payoffer(ctx, screen); break;
        case DLG_DNS_REC:     d_dns_rec(ctx, screen); break;
        case DLG_DNS_CLEAR:   d_dns_clear(ctx, screen); break;
        case DLG_SSL_SUB:     d_ssl_sub(ctx, screen); break;
        case DLG_SSL_DEL:     d_ssl_del(ctx, screen); break;
        case DLG_CONSENT:     d_consent(ctx, screen); break;
        case DLG_BACKUP:      d_backup(ctx, screen); break;
        case DLG_REVEAL_PHRASE:  d_reveal_phrase(ctx, screen); break;
        case DLG_RESTORE_PHRASE: d_restore_phrase(ctx, screen); break;
        case DLG_LOCKED:      d_locked(ctx, screen); break;
        default: break;
    }
}
