// draw.c — canvas kit implementation. Flat fills, 1px borders, nothing else.
#include "draw.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../../vendor/sokol/sokol_app.h"

// ── frame + clip stack ───────────────────────────────────────────────────────
#define CLIP_MAX 8
static struct { struct nk_rect st[CLIP_MAX]; int n; int locked; } D;

struct nk_command_buffer *dk_cv(struct nk_context *ctx) {
    return nk_window_get_canvas(ctx);
}

void dk_frame_begin(struct nk_context *ctx) {
    (void)ctx;
    D.n = 0;
    D.locked = 0;
    sapp_set_mouse_cursor(SAPP_MOUSECURSOR_DEFAULT);
}

void dk_lock_input(int lock);      // modal gate (declared here, used by ui.c)
void dk_lock_input(int lock) { D.locked = lock; }

static struct nk_rect clip_top(void) {
    return D.n ? D.st[D.n - 1] : nk_rect(-16384, -16384, 32768, 32768);
}
static struct nk_rect isect(struct nk_rect a, struct nk_rect b) {
    float x0 = a.x > b.x ? a.x : b.x, y0 = a.y > b.y ? a.y : b.y;
    float x1 = (a.x + a.w < b.x + b.w) ? a.x + a.w : b.x + b.w;
    float y1 = (a.y + a.h < b.y + b.h) ? a.y + a.h : b.y + b.h;
    return nk_rect(x0, y0, x1 > x0 ? x1 - x0 : 0, y1 > y0 ? y1 - y0 : 0);
}

void dk_clip_push(struct nk_context *ctx, struct nk_rect r) {
    struct nk_rect c = isect(clip_top(), r);
    if (D.n < CLIP_MAX) D.st[D.n++] = c;
    nk_push_scissor(dk_cv(ctx), c);
}
void dk_clip_pop(struct nk_context *ctx) {
    if (D.n > 0) D.n--;
    nk_push_scissor(dk_cv(ctx), clip_top());
}

// ── input ────────────────────────────────────────────────────────────────────
static int in_clip(struct nk_context *ctx) {
    struct nk_vec2 m = ctx->input.mouse.pos;
    struct nk_rect c = clip_top();
    return m.x >= c.x && m.x < c.x + c.w && m.y >= c.y && m.y < c.y + c.h;
}
int dk_hot(struct nk_context *ctx, struct nk_rect r) {
    if (D.locked) return 0;
    return in_clip(ctx) && nk_input_is_mouse_hovering_rect(&ctx->input, r);
}
int dk_click(struct nk_context *ctx, struct nk_rect r) {
    if (D.locked) return 0;
    return in_clip(ctx) && nk_input_mouse_clicked(&ctx->input, NK_BUTTON_LEFT, r);
}
int dk_down(struct nk_context *ctx, struct nk_rect r) {
    if (D.locked) return 0;
    return in_clip(ctx) && ctx->input.mouse.buttons[NK_BUTTON_LEFT].down &&
           nk_input_is_mouse_hovering_rect(&ctx->input, r);
}

// ── text ─────────────────────────────────────────────────────────────────────
static const struct nk_color NOBG = { 0, 0, 0, 0 };

float dk_w(ThemeFont f, const char *s) {
    const struct nk_user_font *uf = theme_uf(f);
    return uf->width(uf->userdata, uf->height, s, (int)strlen(s));
}
void dk_text(struct nk_context *ctx, ThemeFont f, float x, float y,
             struct nk_color col, const char *s) {
    const struct nk_user_font *uf = theme_uf(f);
    int len = (int)strlen(s);
    float w = uf->width(uf->userdata, uf->height, s, len);
    nk_draw_text(dk_cv(ctx), nk_rect(x, y, w + 2, uf->height), s, len, uf, NOBG, col);
}
void dk_text_r(struct nk_context *ctx, ThemeFont f, float xr, float y,
               struct nk_color col, const char *s) {
    dk_text(ctx, f, xr - dk_w(f, s), y, col, s);
}
void dk_text_c(struct nk_context *ctx, ThemeFont f, struct nk_rect r,
               struct nk_color col, const char *s) {
    float w = dk_w(f, s), h = theme_lineh(f);
    dk_text(ctx, f, r.x + (r.w - w) / 2, r.y + (r.h - h) / 2, col, s);
}

float dk_w_sp(ThemeFont f, const char *s, float sp) {
    const struct nk_user_font *uf = theme_uf(f);
    float w = 0; int len = (int)strlen(s), i = 0;
    while (i < len) {
        nk_rune cp; int n = nk_utf_decode(s + i, &cp, len - i);
        if (!n) break;
        w += uf->width(uf->userdata, uf->height, s + i, n) + sp;
        i += n;
    }
    return w > 0 ? w - sp : 0;
}
float dk_text_sp(struct nk_context *ctx, ThemeFont f, float x, float y,
                 struct nk_color col, const char *s, float sp) {
    const struct nk_user_font *uf = theme_uf(f);
    float x0 = x; int len = (int)strlen(s), i = 0;
    while (i < len) {
        nk_rune cp; int n = nk_utf_decode(s + i, &cp, len - i);
        if (!n) break;
        float cw = uf->width(uf->userdata, uf->height, s + i, n);
        nk_draw_text(dk_cv(ctx), nk_rect(x, y, cw + 2, uf->height), s + i, n, uf, NOBG, col);
        x += cw + sp;
        i += n;
    }
    return x - sp - x0;
}

// greedy word wrap; '\n' honored; over-long words broken at codepoints
float dk_wrap(struct nk_context *ctx, ThemeFont f, float x, float y, float w,
              struct nk_color col, const char *s, float line_mult) {
    const struct nk_user_font *uf = theme_uf(f);
    float lh = uf->height * (line_mult > 0 ? line_mult : 1.3f);
    int len = (int)strlen(s), pos = 0;
    while (pos < len) {
        int line_end = pos, cursor = pos, last_fit = pos;
        float lw = 0;
        while (cursor < len && s[cursor] != '\n') {
            // next word (incl. leading space)
            int we = cursor;
            while (we < len && s[we] == ' ') we++;
            while (we < len && s[we] != ' ' && s[we] != '\n') we++;
            float ww = uf->width(uf->userdata, uf->height, s + cursor, we - cursor);
            if (lw + ww > w && last_fit > pos) break;             // wrap before word
            if (lw + ww > w) {                                    // word alone too wide
                int ce = cursor;
                while (ce < we) {
                    nk_rune cp; int n = nk_utf_decode(s + ce, &cp, len - ce);
                    if (!n) { ce = we; break; }
                    float cw = uf->width(uf->userdata, uf->height, s + ce, n);
                    if (lw + cw > w && ce > pos) break;
                    lw += cw; ce += n;
                }
                cursor = last_fit = ce;
                break;
            }
            lw += ww; cursor = we; last_fit = we;
        }
        line_end = (last_fit > pos) ? last_fit : (cursor > pos ? cursor : pos + 1);
        if (ctx) {
            int a = pos;
            while (a < line_end && s[a] == ' ') a++;              // trim leading space
            if (line_end > a)
                nk_draw_text(dk_cv(ctx), nk_rect(x, y, w + 2, uf->height),
                             s + a, line_end - a, uf, NOBG, col);
        }
        y += lh;
        pos = line_end;
        if (pos < len && s[pos] == '\n') pos++;
    }
    return y;
}

// ── shapes ───────────────────────────────────────────────────────────────────
void dk_fill(struct nk_context *ctx, struct nk_rect r, float rad, struct nk_color c) {
    nk_fill_rect(dk_cv(ctx), r, rad, c);
}
void dk_line_rect(struct nk_context *ctx, struct nk_rect r, float rad, struct nk_color c) {
    nk_stroke_rect(dk_cv(ctx), r, rad, 1.0f, c);
}
void dk_card(struct nk_context *ctx, struct nk_rect r, float rad,
             struct nk_color fill, struct nk_color border) {
    nk_fill_rect(dk_cv(ctx), r, rad, fill);
    nk_stroke_rect(dk_cv(ctx), r, rad, 1.0f, border);
}
void dk_hline(struct nk_context *ctx, float x0, float x1, float y, struct nk_color c) {
    nk_fill_rect(dk_cv(ctx), nk_rect(x0, y, x1 - x0, 1), 0, c);
}
void dk_hline_dashed(struct nk_context *ctx, float x0, float x1, float y, struct nk_color c) {
    for (float x = x0; x < x1; x += 7)
        nk_fill_rect(dk_cv(ctx), nk_rect(x, y, x + 4 > x1 ? x1 - x : 4, 1), 0, c);
}
static void vline_dashed(struct nk_context *ctx, float x, float y0, float y1, struct nk_color c) {
    for (float y = y0; y < y1; y += 7)
        nk_fill_rect(dk_cv(ctx), nk_rect(x, y, 1, y + 4 > y1 ? y1 - y : 4), 0, c);
}
void dk_rect_dashed(struct nk_context *ctx, struct nk_rect r, float rad, struct nk_color c) {
    (void)rad;   // corners stay open — flat look, dashes only along the edges
    dk_hline_dashed(ctx, r.x + 4, r.x + r.w - 4, r.y, c);
    dk_hline_dashed(ctx, r.x + 4, r.x + r.w - 4, r.y + r.h - 1, c);
    vline_dashed(ctx, r.x, r.y + 4, r.y + r.h - 4, c);
    vline_dashed(ctx, r.x + r.w - 1, r.y + 4, r.y + r.h - 4, c);
}
void dk_dot(struct nk_context *ctx, float cx, float cy, float d, struct nk_color c) {
    nk_fill_circle(dk_cv(ctx), nk_rect(cx - d / 2, cy - d / 2, d, d), c);
}
void dk_ring(struct nk_context *ctx, float cx, float cy, float d, struct nk_color c) {
    nk_stroke_circle(dk_cv(ctx), nk_rect(cx - d / 2, cy - d / 2, d, d), 1.0f, c);
}
void dk_progress(struct nk_context *ctx, struct nk_rect r, float frac,
                 struct nk_color track, struct nk_color fill) {
    if (frac < 0) frac = 0; if (frac > 1) frac = 1;
    nk_fill_rect(dk_cv(ctx), r, r.h / 2, track);
    if (frac > 0.01f)
        nk_fill_rect(dk_cv(ctx), nk_rect(r.x, r.y, r.w * frac, r.h), r.h / 2, fill);
}
void dk_icon_copy(struct nk_context *ctx, float x, float y, float s, struct nk_color c) {
    float o = s * 0.30f;
    nk_stroke_rect(dk_cv(ctx), nk_rect(x + o, y, s - o, s - o), 2, 1.0f, c);
    nk_fill_rect(dk_cv(ctx), nk_rect(x, y + o, s - o, s - o), 2, C_PANEL);
    nk_stroke_rect(dk_cv(ctx), nk_rect(x, y + o, s - o, s - o), 2, 1.0f, c);
}

// 3×3 identicon: FNV-1a of the name picks the content color and the cell
// pattern (guaranteed ≥3 lit cells so no name draws an empty tile)
void dk_identicon(struct nk_context *ctx, float x, float y, float cell,
                  float gap, const char *name, int dimmed) {
    uint32_t h = 2166136261u;
    for (const char *p = name; *p; p++) { h ^= (uint8_t)*p; h *= 16777619u; }
    static const struct nk_color CC[5] = {
        { (TH_ACCENT >> 16) & 0xFF, (TH_ACCENT >> 8) & 0xFF, TH_ACCENT & 0xFF, 255 },
        { (TH_OK >> 16) & 0xFF, (TH_OK >> 8) & 0xFF, TH_OK & 0xFF, 255 },
        { (TH_ID_BLUE >> 16) & 0xFF, (TH_ID_BLUE >> 8) & 0xFF, TH_ID_BLUE & 0xFF, 255 },
        { (TH_ID_PURPLE >> 16) & 0xFF, (TH_ID_PURPLE >> 8) & 0xFF, TH_ID_PURPLE & 0xFF, 255 },
        { (TH_ID_TAN >> 16) & 0xFF, (TH_ID_TAN >> 8) & 0xFF, TH_ID_TAN & 0xFF, 255 },
    };
    struct nk_color on = dimmed ? C_GHOST : CC[h % 5];
    unsigned bits = (h >> 3) & 0x1FF;
    { int lit = 0; for (int i = 0; i < 9; i++) lit += (bits >> i) & 1;
      if (lit < 3) bits |= 0x111; }               // diagonal floor
    for (int r = 0; r < 3; r++)
        for (int c = 0; c < 3; c++) {
            int lit = (bits >> (r * 3 + c)) & 1;
            nk_fill_rect(dk_cv(ctx),
                         nk_rect(x + c * (cell + gap), y + r * (cell + gap),
                                 cell, cell),
                         3, lit ? on : C_INPUT);
        }
}

// ── components ───────────────────────────────────────────────────────────────
static struct nk_color colmul(struct nk_color c, float k) {
    int r = (int)(c.r * k), g = (int)(c.g * k), b = (int)(c.b * k);
    return nk_rgb(r > 255 ? 255 : r, g > 255 ? 255 : g, b > 255 ? 255 : b);
}

int dk_btn_col(struct nk_context *ctx, struct nk_rect r, ThemeFont f,
               const char *label, BtnStyle st, struct nk_color text_override) {
    int hot = dk_hot(ctx, r), down = hot && dk_down(ctx, r);
    float rad = r.h >= 40 ? 10 : (r.h >= 30 ? 8 : 6);
    struct nk_color fill, text;
    int bordered = 0;
    switch (st) {
        case BTN_ACCENT:  fill = C_ACCENT;  text = C_ONFILL; break;
        case BTN_GREEN: fill = C_GREEN; text = C_ONFILL; break;
        case BTN_RED:   fill = C_RED;   text = C_ONFILL; break;
        case BTN_LINE_FILL: fill = C_INPUT; text = C_TEXT; bordered = 1; break;
        case BTN_GHOST: fill = NOBG; text = C_GHOST; break;
        default:        fill = NOBG; text = C_DIM; bordered = 1; break;   // BTN_LINE
    }
    if (text_override.a) text = text_override;
    if (st == BTN_GHOST) {
        if (hot) text = C_DIM;
        dk_text(ctx, f, r.x, r.y + (r.h - theme_lineh(f)) / 2, text, label);
        if (hot) sapp_set_mouse_cursor(SAPP_MOUSECURSOR_POINTING_HAND);
        return dk_click(ctx, r);
    }
    if (bordered) {
        if (hot) fill = (st == BTN_LINE_FILL) ? C_PRESS : C_INPUT;
        if (fill.a) nk_fill_rect(dk_cv(ctx), r, rad, fill);
        nk_stroke_rect(dk_cv(ctx), r, rad, 1.0f, down ? C_ACCENT : C_BORDER);
    } else {
        if (down) fill = colmul(fill, 0.92f);
        else if (hot) fill = colmul(fill, 1.07f);
        nk_fill_rect(dk_cv(ctx), r, rad, fill);
    }
    dk_text_c(ctx, f, r, text, label);
    if (hot) sapp_set_mouse_cursor(SAPP_MOUSECURSOR_POINTING_HAND);
    return dk_click(ctx, r);
}
int dk_btn(struct nk_context *ctx, struct nk_rect r, ThemeFont f,
           const char *label, BtnStyle st) {
    return dk_btn_col(ctx, r, f, label, st, NOBG);
}

float dk_badge_w(const char *label) { return dk_w_sp(F_SMB9, label, 1) + 16; }
float dk_badge(struct nk_context *ctx, float x, float y, const char *label, BadgeStyle st) {
    float w = dk_badge_w(label), h = 15;
    struct nk_rect r = nk_rect(x, y, w, h);
    switch (st) {
        case BADGE_FILL_GREEN:
            nk_fill_rect(dk_cv(ctx), r, 4, C_GREEN);
            dk_text_sp(ctx, F_SMB9, x + 8, y + (h - theme_lineh(F_SMB9)) / 2, C_ONFILL, label, 1);
            break;
        case BADGE_FILL_ACCENT:
            nk_fill_rect(dk_cv(ctx), r, 4, C_ACCENT);
            dk_text_sp(ctx, F_SMB9, x + 8, y + (h - theme_lineh(F_SMB9)) / 2, C_ONFILL, label, 1);
            break;
        case BADGE_LINE_ACCENT:
            nk_stroke_rect(dk_cv(ctx), r, 4, 1.0f, C_ACCENT);
            dk_text_sp(ctx, F_SMB9, x + 8, y + (h - theme_lineh(F_SMB9)) / 2, C_ACCENT, label, 1);
            break;
        default:
            nk_stroke_rect(dk_cv(ctx), r, 4, 1.0f, C_GREEN);
            dk_text_sp(ctx, F_SMB9, x + 8, y + (h - theme_lineh(F_SMB9)) / 2, C_GREEN, label, 1);
            break;
    }
    return w;
}

float dk_count_pill(struct nk_context *ctx, float xr, float cy, int n) {
    char b[16]; snprintf(b, sizeof b, "%d", n);
    float tw = dk_w(F_SMB10, b);
    float w = tw + 12 < 16 ? 16 : tw + 12, h = 15;
    struct nk_rect r = nk_rect(xr - w, cy - h / 2, w, h);
    nk_fill_rect(dk_cv(ctx), r, h / 2, C_ACCENT);
    dk_text_c(ctx, F_SMB10, r, C_ONFILL, b);
    return w;
}

int dk_scrim(struct nk_context *ctx, struct nk_rect screen) {
    nk_fill_rect(dk_cv(ctx), screen, 0, nk_rgba(15, 14, 12, 150));
    return nk_input_mouse_clicked(&ctx->input, NK_BUTTON_LEFT, screen);
}

// ── scroll region ────────────────────────────────────────────────────────────
void dk_scroll_begin(struct nk_context *ctx, DkScroll *s, struct nk_rect view) {
    (void)s;
    dk_clip_push(ctx, view);
}

void dk_scroll_end(struct nk_context *ctx, DkScroll *s, struct nk_rect view,
                   float content_h, int bottom_stick) {
    dk_clip_pop(ctx);
    s->content_h = content_h;
    float max = content_h - view.h;
    if (max < 0) max = 0;

    struct nk_input *in = &ctx->input;
    int over = !D.locked && nk_input_is_mouse_hovering_rect(in, view);
    float wheel = in->mouse.scroll_delta.y;
    if (over && wheel != 0) {
        s->scroll -= wheel * 42.0f;
        if (bottom_stick) s->stick = (s->scroll >= max - 2);
        in->mouse.scroll_delta.y = 0;
    }
    if (bottom_stick && s->stick) s->scroll = max;
    if (s->scroll < 0) s->scroll = 0;
    if (s->scroll > max) s->scroll = max;

    if (max > 0) {                                       // 4px thumb, inset 4
        float trk_h = view.h - 10;
        float th = trk_h * (view.h / content_h);
        if (th < 24) th = 24;
        float ty = view.y + 5 + (trk_h - th) * (max > 0 ? s->scroll / max : 0);
        struct nk_rect thumb = nk_rect(view.x + view.w - 8, ty, 4, th);
        struct nk_rect track = nk_rect(view.x + view.w - 10, view.y, 10, view.h);
        if (!D.locked && in->mouse.buttons[NK_BUTTON_LEFT].down &&
            (s->dragging || nk_input_is_mouse_hovering_rect(in, track))) {
            if (!s->dragging) { s->dragging = 1; s->grab = in->mouse.pos.y - ty; }
            float ny = in->mouse.pos.y - s->grab - (view.y + 5);
            s->scroll = (trk_h - th) > 0 ? ny / (trk_h - th) * max : 0;
            if (bottom_stick) s->stick = (s->scroll >= max - 2);
            if (s->scroll < 0) s->scroll = 0;
            if (s->scroll > max) s->scroll = max;
        } else {
            s->dragging = 0;
        }
        nk_fill_rect(dk_cv(ctx), thumb, 2, s->dragging ? C_GHOST : C_BORDER);
    }
}

// ── formatting ───────────────────────────────────────────────────────────────
static void thousands(char *out, size_t cap, long long v) {
    char raw[32]; snprintf(raw, sizeof raw, "%lld", v);
    int len = (int)strlen(raw), o = 0;
    for (int i = 0; i < len && (size_t)o + 2 < cap; i++) {
        if (i > 0 && (len - i) % 3 == 0 && raw[i - 1] != '-') out[o++] = ',';
        out[o++] = raw[i];
    }
    out[o] = 0;
}
void fmt_thousands(char *out, size_t cap, int64_t n) { thousands(out, cap, (long long)n); }

void fmt_amount(char *out, size_t cap, int64_t koinu) {
    long long ip = koinu / 100000000LL, fp = koinu % 100000000LL;
    if (fp < 0) fp = -fp;
    char ips[32]; thousands(ips, sizeof ips, ip);
    if (fp == 0) { snprintf(out, cap, "%s", ips); return; }
    char frac[16]; snprintf(frac, sizeof frac, "%08lld", fp);
    int e = 7; while (e > 0 && frac[e] == '0') e--;
    frac[e + 1] = 0;
    snprintf(out, cap, "%s.%s", ips, frac);
}
void fmt_amount_p(char *out, size_t cap, int64_t koinu) {
    char a[48]; fmt_amount(a, sizeof a, koinu);
    snprintf(out, cap, GLY_P " %s", a);
}
void fmt_amount_sp(char *out, size_t cap, int64_t koinu) {
    char a[48]; fmt_amount(a, sizeof a, koinu);
    snprintf(out, cap, "%s " GLY_P, a);
}
// display-rounded to 4 decimals (dialog cost rows — exact koinu still moves)
void fmt_amount4_sp(char *out, size_t cap, int64_t koinu) {
    int64_t r = (koinu + 5000) / 10000 * 10000;
    fmt_amount_sp(out, cap, r);
}

void fmt_addr_short(char *out, size_t cap, const char *addr) {
    size_t n = strlen(addr);
    if (n <= 13) { snprintf(out, cap, "%s", addr); return; }
    snprintf(out, cap, "%.6s…%s", addr, addr + n - 5);
}

void fmt_kcount(char *out, size_t cap, int64_t n) {
    if (n < 1000) { snprintf(out, cap, "%lld", (long long)n); return; }
    if (n < 10000) {
        long long t = n / 100;                            // one decimal
        if (t % 10) snprintf(out, cap, "%lld.%lldk", t / 10, t % 10);
        else snprintf(out, cap, "%lldk", t / 10);
        return;
    }
    snprintf(out, cap, "%lldk", (long long)(n / 1000));
}

void fmt_days_left(char *out, size_t cap, int64_t secs) {
    if (secs < 0) secs = 0;
    if (secs >= 86400)      snprintf(out, cap, "%lldd", (long long)(secs / 86400));
    else if (secs >= 3600)  snprintf(out, cap, "%lldh", (long long)(secs / 3600));
    else                    snprintf(out, cap, "%lldm", (long long)(secs / 60));
}
void fmt_hms(char *out, size_t cap, int64_t secs) {
    if (secs < 0) secs = 0;
    snprintf(out, cap, "%02lld:%02lld:%02lld", (long long)(secs / 3600),
             (long long)((secs / 60) % 60), (long long)(secs % 60));
}
void fmt_time_hm(char *out, size_t cap, int64_t t) {
    time_t tt = (time_t)t; struct tm tm;
    localtime_r(&tt, &tm);
    snprintf(out, cap, "%02d:%02d", tm.tm_hour, tm.tm_min);
}
static void lower(char *s) { for (; *s; s++) if (*s >= 'A' && *s <= 'Z') *s += 32; }
void fmt_date_short(char *out, size_t cap, int64_t t) {
    time_t tt = (time_t)t; struct tm tm;
    localtime_r(&tt, &tm);
    char mon[8]; strftime(mon, sizeof mon, "%b", &tm); lower(mon);
    snprintf(out, cap, "%s %d", mon, tm.tm_mday);
}
void fmt_date_long(char *out, size_t cap, int64_t t) {
    time_t tt = (time_t)t; struct tm tm;
    localtime_r(&tt, &tm);
    char mon[8]; strftime(mon, sizeof mon, "%b", &tm); lower(mon);
    snprintf(out, cap, "%s %d, %d", mon, tm.tm_mday, tm.tm_year + 1900);
}
void fmt_bytes_kb(char *out, size_t cap, int64_t b) {
    if (b >= 1000000) snprintf(out, cap, "%.1f MB", (double)b / 1000000.0);
    else snprintf(out, cap, "%lld KB", (long long)(b / 1000));
}

// money in must be as strict as money out: no atof (it swallows "1e9", "  5",
// "1.2.3"). Digits, at most one dot, at most 8 decimals — or it's not a number.
int fmt_parse_amount(const char *s, int64_t *out) {
    if (!s) return 0;
    int64_t ip = 0, frac = 0, scale = 10000000LL;
    int idig = 0, fdig = 0;
    for (; *s >= '0' && *s <= '9'; s++, idig++) {
        ip = ip * 10 + (*s - '0');
        if (ip > 92233720368LL) return 0;              // koinu would overflow
    }
    if (*s == '.') {
        for (s++; *s >= '0' && *s <= '9'; s++, fdig++) {
            if (fdig >= 8) return 0;                   // sub-koinu precision
            frac += (int64_t)(*s - '0') * scale;
            scale /= 10;
        }
    }
    if (*s || (!idig && !fdig)) return 0;              // junk, or "" / "."
    *out = ip * 100000000LL + frac;
    return 1;
}
