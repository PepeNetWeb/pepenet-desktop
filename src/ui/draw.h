// draw.h — the canvas kit every screen is built from.
//
// The whole app is owner-drawn: one full-window nk canvas, absolute rects,
// flat fills + 1px borders only (the Nuklear-safe constraint the design was
// authored under). These helpers encode the §1a component grammar:
//   filled gold  = spends money      bordered = safe
//   hover        = bg one step up    pressed  = border turns gold
#ifndef SHIB_DRAW_H
#define SHIB_DRAW_H

#include "nk_config.h"
#include "theme.h"
#include <stdint.h>

// ── frame plumbing ───────────────────────────────────────────────────────────
void dk_frame_begin(struct nk_context *ctx);     // resets clip stack + cursor
struct nk_command_buffer *dk_cv(struct nk_context *ctx);

// clip stack — scrolled regions push their viewport so hit-tests can't leak
void dk_clip_push(struct nk_context *ctx, struct nk_rect r);
void dk_clip_pop(struct nk_context *ctx);

// ── input ────────────────────────────────────────────────────────────────────
int dk_hot(struct nk_context *ctx, struct nk_rect r);     // hover (clip-aware)
int dk_click(struct nk_context *ctx, struct nk_rect r);   // LMB click (clip-aware)
int dk_down(struct nk_context *ctx, struct nk_rect r);    // LMB held on rect

// ── text ─────────────────────────────────────────────────────────────────────
float dk_w(ThemeFont f, const char *s);                       // width
void  dk_text(struct nk_context *ctx, ThemeFont f, float x, float y,
              struct nk_color col, const char *s);
void  dk_text_r(struct nk_context *ctx, ThemeFont f, float xr, float y,
                struct nk_color col, const char *s);          // right-aligned
void  dk_text_c(struct nk_context *ctx, ThemeFont f, struct nk_rect r,
                struct nk_color col, const char *s);          // centered (h+v)
// letter-spaced caps labels (SM 9px, +1px tracking); returns width
float dk_text_sp(struct nk_context *ctx, ThemeFont f, float x, float y,
                 struct nk_color col, const char *s, float sp);
float dk_w_sp(ThemeFont f, const char *s, float sp);
// greedy word-wrap; ctx==NULL measures only; returns y below the last line
float dk_wrap(struct nk_context *ctx, ThemeFont f, float x, float y, float w,
              struct nk_color col, const char *s, float line_mult);

// ── shapes ───────────────────────────────────────────────────────────────────
void dk_fill(struct nk_context *ctx, struct nk_rect r, float rad, struct nk_color c);
void dk_line_rect(struct nk_context *ctx, struct nk_rect r, float rad, struct nk_color c);
void dk_card(struct nk_context *ctx, struct nk_rect r, float rad,
             struct nk_color fill, struct nk_color border);
void dk_hline(struct nk_context *ctx, float x0, float x1, float y, struct nk_color c);
void dk_hline_dashed(struct nk_context *ctx, float x0, float x1, float y, struct nk_color c);
void dk_rect_dashed(struct nk_context *ctx, struct nk_rect r, float rad, struct nk_color c);
void dk_dot(struct nk_context *ctx, float cx, float cy, float d, struct nk_color c);
void dk_ring(struct nk_context *ctx, float cx, float cy, float d, struct nk_color c);
void dk_progress(struct nk_context *ctx, struct nk_rect r, float frac,
                 struct nk_color track, struct nk_color fill);
void dk_icon_copy(struct nk_context *ctx, float x, float y, float s, struct nk_color c);
// 3×3 identicon (9a card art): a hash of the name picks the content color +
// cell pattern — deterministic, no site fetch. dimmed = the lapsed variant.
void dk_identicon(struct nk_context *ctx, float x, float y, float cell,
                  float gap, const char *name, int dimmed);

// ── components ───────────────────────────────────────────────────────────────
typedef enum { BTN_ACCENT, BTN_GREEN, BTN_RED, BTN_LINE, BTN_LINE_FILL, BTN_GHOST } BtnStyle;
// bordered button base fill: BTN_LINE = transparent, BTN_LINE_FILL = C_INPUT
int  dk_btn(struct nk_context *ctx, struct nk_rect r, ThemeFont f,
            const char *label, BtnStyle st);
int  dk_btn_col(struct nk_context *ctx, struct nk_rect r, ThemeFont f,
                const char *label, BtnStyle st, struct nk_color text_override);

typedef enum { BADGE_FILL_GREEN, BADGE_FILL_ACCENT, BADGE_LINE_ACCENT, BADGE_LINE_GREEN } BadgeStyle;
float dk_badge(struct nk_context *ctx, float x, float y, const char *label,
               BadgeStyle st);                                 // returns width
float dk_badge_w(const char *label);

// gold count pill (rail unread): returns width
float dk_count_pill(struct nk_context *ctx, float xr, float cy, int n);

// modal scrim: dims + swallows input under dialogs; true if backdrop clicked
int dk_scrim(struct nk_context *ctx, struct nk_rect screen);

// ── scroll region ────────────────────────────────────────────────────────────
typedef struct {
    float scroll;          // px scrolled from top
    int   stick;           // stick to bottom while content grows (feeds)
    float content_h;       // measured content height (set by end)
    int   dragging;        // scrollbar thumb drag
    float grab;
} DkScroll;
// begin pushes the scissor; caller draws content offset by -s->scroll
void dk_scroll_begin(struct nk_context *ctx, DkScroll *s, struct nk_rect view);
// end: consumes wheel, clamps, draws the 4px thumb, pops the scissor
void dk_scroll_end(struct nk_context *ctx, DkScroll *s, struct nk_rect view,
                   float content_h, int bottom_stick);

// ── formatting (Space Mono truth strings) ────────────────────────────────────
#define GLY_P "\xE2\xB1\xA3"          // Ᵽ U+2C63
void fmt_amount(char *out, size_t cap, int64_t koinu);            // "12.401"
void fmt_amount_p(char *out, size_t cap, int64_t koinu);          // "Ᵽ 12.401"
void fmt_amount_sp(char *out, size_t cap, int64_t koinu);         // "12.401 Ᵽ"
void fmt_amount4_sp(char *out, size_t cap, int64_t koinu);        // ≤4 dp: "0.0301 Ᵽ"
void fmt_addr_short(char *out, size_t cap, const char *addr);     // Pu…hFL 6…5
void fmt_kcount(char *out, size_t cap, int64_t n);                // 3.1k / 44k
void fmt_days_left(char *out, size_t cap, int64_t secs);          // 12d / 22h / 40m
void fmt_hms(char *out, size_t cap, int64_t secs);                // 23:41:08
void fmt_time_hm(char *out, size_t cap, int64_t t);               // 10:04
void fmt_date_short(char *out, size_t cap, int64_t t);            // jun 28
void fmt_date_long(char *out, size_t cap, int64_t t);             // apr 2, 2027
void fmt_bytes_kb(char *out, size_t cap, int64_t b);              // 819 KB / 1.0 MB
void fmt_thousands(char *out, size_t cap, int64_t n);             // 4,213,882
// strict "12.34" → koinu: digits + at most one dot + ≤8 decimals, nothing else
int  fmt_parse_amount(const char *s, int64_t *out);               // 1 = valid

#endif
