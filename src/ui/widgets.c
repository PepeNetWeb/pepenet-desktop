// widgets.c — shared composites: headers, the balance chip, styled edit
// fields, steppers.
#include "ui.h"

#include "../../vendor/sokol/sokol_app.h"

#include <stdio.h>
#include <string.h>

// ── popup opener: the click that opens a panel is still live in nk's input
//    this frame — popups_draw must not read it as a click OUTSIDE the panel
//    (it lands on the trigger) and close what it just opened ────────────────
void ui_popup_open(Popup p, struct nk_rect anchor) {
    UI.popup = p;
    UI.pop_anchor = anchor;
    UI.pop_guard = 1;
}

// ── dead button: same geometry as dk_btn, unmistakably inert ────────────────
void ui_btn_disabled(struct nk_context *ctx, struct nk_rect r, ThemeFont f,
                     const char *label) {
    float rad = r.h >= 40 ? 10 : (r.h >= 30 ? 8 : 6);   // dk_btn's radius rule
    dk_card(ctx, r, rad, C_BG, C_HAIR);
    dk_text_c(ctx, f, r, C_GHOST, label);
}

// ── toggle switch: pill + sliding knob; returns 1 on click (caller flips) ────
int ui_toggle(struct nk_context *ctx, struct nk_rect r, int on) {
    dk_fill(ctx, r, r.h / 2, on ? C_ACCENT : C_INPUT);
    if (!on) dk_line_rect(ctx, r, r.h / 2, C_BORDER);
    float pad = 3, d = r.h - 2 * pad;
    struct nk_rect knob = nk_rect(on ? r.x + r.w - pad - d : r.x + pad,
                                  r.y + pad, d, d);
    dk_fill(ctx, knob, d / 2, on ? C_ONFILL : C_DIM);
    if (dk_hot(ctx, r)) sapp_set_mouse_cursor(SAPP_MOUSECURSOR_POINTING_HAND);
    return dk_click(ctx, r);
}

// ── screen header (‹ back + title) — the dropdown views (Send · Receive ·
//    Settings); back returns to whichever tab the user came from ─────────────
void ui_screen_header(struct nk_context *ctx, struct nk_rect area,
                      const char *title) {
    float y = area.y;
    struct nk_rect back = nk_rect(area.x + 8, y + 6, 30, 34);
    dk_text(ctx, F_SM16, area.x + 16, y + 12, dk_hot(ctx, back) ? C_DIM : C_GHOST, "\xE2\x80\xB9");
    if (dk_click(ctx, back)) { UI.view = UI.last_tab; UI.popup = POP_NONE; }
    dk_text(ctx, F_PH22, area.x + 40, y + 9, C_TEXT, title);
    dk_hline(ctx, area.x, area.x + area.w, y + 45, C_BORDER);
}

// ── per-name sub-header (9c/9d): ‹ back → My Names · name + TLD · "· which" ·
//    cross-link to the sibling screen at the right edge ──────────────────────
float ui_name_header(struct nk_context *ctx, struct nk_rect area,
                     const char *name, const char *which,
                     const char *other_label, View other_view) {
    float y = area.y;
    struct nk_rect back = nk_rect(area.x + 8, y + 5, 30, 36);
    dk_text(ctx, F_SM16, area.x + 16, y + 13, dk_hot(ctx, back) ? C_DIM : C_GHOST,
            "\xE2\x80\xB9");
    if (dk_hot(ctx, back)) sapp_set_mouse_cursor(SAPP_MOUSECURSOR_POINTING_HAND);
    if (dk_click(ctx, back)) { UI.view = V_NAMES; UI.popup = POP_NONE; }
    float x = area.x + 40;
    dk_text(ctx, F_PH22, x, y + 8, C_TEXT, name);
    x += dk_w(F_PH22, name);
    dk_text(ctx, F_SM16, x, y + 14, C_ACCENT, APP_DOT_TLD);
    x += dk_w(F_SM16, APP_DOT_TLD) + 8;
    char wl[24];
    snprintf(wl, sizeof wl, "\xC2\xB7 %s", which);
    dk_text(ctx, F_PH14, x, y + 14, C_GHOST, wl);
    if (other_label) {
        float lw = dk_w(F_PH14, other_label);
        struct nk_rect lk = nk_rect(area.x + area.w - 16 - lw - 8, y + 8, lw + 12, 30);
        int hot = dk_hot(ctx, lk);
        dk_text_r(ctx, F_PH14, area.x + area.w - 16, y + 14,
                  hot ? C_TEXT : C_DIM, other_label);
        if (hot) sapp_set_mouse_cursor(SAPP_MOUSECURSOR_POINTING_HAND);
        if (dk_click(ctx, lk)) { UI.view = other_view; UI.popup = POP_NONE; }
    }
    dk_hline(ctx, area.x, area.x + area.w, y + 46, C_HAIR);
    return y + 47;
}

// ── balance chip: dot = sync state, amount, caret ────────────────────────────
int ui_balance_chip(struct nk_context *ctx, float xr, float cy) {
    char amt[48];
    fmt_amount_p(amt, sizeof amt, M.balance);
    int open = (UI.popup == POP_BALANCE);
    float w = 7 + 7 + dk_w(F_SM13, amt) + 7 + dk_w(F_SM10, "\xE2\x96\xBE") + 11 + 11;
    struct nk_rect r = nk_rect(xr - w, cy - 14, w, 28);
    dk_card(ctx, r, 8, C_PANEL, open ? C_ACCENT : C_BORDER);
    struct nk_color dot = M.demo || M.synced ? C_GREEN : (M.syncing ? C_ACCENT : C_RED);
    dk_dot(ctx, r.x + 14, cy, 7, dot);
    dk_text(ctx, F_SM13, r.x + 21, cy - theme_lineh(F_SM13) / 2, C_TEXT, amt);
    dk_text_r(ctx, F_SM10, r.x + r.w - 10, cy - theme_lineh(F_SM10) / 2,
              open ? C_ACCENT : C_GHOST, open ? "\xE2\x96\xB4" : "\xE2\x96\xBE");
    if (dk_hot(ctx, r)) sapp_set_mouse_cursor(SAPP_MOUSECURSOR_POINTING_HAND);
    if (dk_click(ctx, r)) { UI.pop_anchor = r; return 1; }
    return 0;
}

void ui_sync_line(char *out, size_t cap) {
    if (M.demo || M.synced) snprintf(out, cap, "%s", TR(S_SYNC_SYNCED));
    else if (M.syncing)     snprintf(out, cap, "%s", TR(S_SYNC_SYNCING));
    else if (M.unreachable) snprintf(out, cap, "%s", TR(S_SYNC_UNREACHABLE));
    else                    snprintf(out, cap, "%s", TR(S_SYNC_CONNECTING));
}

// ── styled single-line edit ──────────────────────────────────────────────────
// bare=1: the caller drew the surrounding card — suppress the edit's own
// border/rounding so it doesn't draw a box inside the box.
int ui_edit(struct nk_context *ctx, struct nk_rect r, char *buf, int *len, int max,
            const char *placeholder, ThemeFont f, int bare) {
    struct nk_vec2 o = nk_layout_space_to_screen(ctx, nk_vec2(0, 0));
    nk_layout_space_push(ctx, nk_rect(r.x - o.x, r.y - o.y, r.w, r.h));
    nk_style_push_font(ctx, theme_uf(f));
    struct nk_style_edit save = ctx->style.edit;
    if (bare) {
        ctx->style.edit.border = 0;
        ctx->style.edit.rounding = 0;
        ctx->style.edit.padding = nk_vec2(4, 4);
    }
    nk_flags fl = nk_edit_string(ctx, NK_EDIT_FIELD | NK_EDIT_SIG_ENTER,
                                 buf, len, max, nk_filter_default);
    ctx->style.edit = save;
    nk_style_pop_font(ctx);
    if (*len == 0 && placeholder) {
        dk_text(ctx, f, r.x + (bare ? 5 : 13), r.y + (r.h - theme_lineh(f)) / 2,
                C_GHOST, placeholder);
    }
    return (fl & NK_EDIT_COMMITED) ? 1 : 0;
}

// ── k/v fee rows (dialogs, send) ─────────────────────────────────────────────
void ui_kv_row(struct nk_context *ctx, float x, float xr, float y,
               const char *k, const char *v, struct nk_color kc, struct nk_color vc) {
    dk_text(ctx, F_SM11, x, y, kc, k);
    dk_text_r(ctx, F_SM11, xr, y, vc, v);
}

// ── stepper: value box with ▲▼ nudges (engrave burn, vote weight) ───────────
int ui_stepper(struct nk_context *ctx, struct nk_rect r, char *valbuf,
               ThemeFont f, struct nk_color valcol) {
    dk_card(ctx, r, 8, C_BG, C_ACCENT);
    dk_text(ctx, F_SM13, r.x + 12, r.y + (r.h - theme_lineh(F_SM13)) / 2, C_GHOST, GLY_P);
    dk_text(ctx, f, r.x + 34, r.y + (r.h - theme_lineh(f)) / 2, valcol, valbuf);
    struct nk_rect up = nk_rect(r.x + r.w - 26, r.y + 3, 22, r.h / 2 - 3);
    struct nk_rect dn = nk_rect(r.x + r.w - 26, r.y + r.h / 2, 22, r.h / 2 - 3);
    dk_text_c(ctx, F_SM10, up, dk_hot(ctx, up) ? C_TEXT : C_GHOST, "\xE2\x96\xB4");
    dk_text_c(ctx, F_SM10, dn, dk_hot(ctx, dn) ? C_TEXT : C_GHOST, "\xE2\x96\xBE");
    if (dk_click(ctx, up)) return +1;
    if (dk_click(ctx, dn)) return -1;
    return 0;
}
