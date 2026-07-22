// theme.c — font atlas + nuklear style table for the pepenet visual system.
//
// Retina-crisp text: every face is baked at logical_size * dpi_scale pixels,
// then its nk handle height is set back to the logical size. Layout runs in
// logical points; sokol-nuklear's dpi_scale blows the vertices back up at
// render time, so baked texels land 1:1 on device pixels.
//
// Glyph sourcing (fetch_vendors.sh + system fallbacks):
//   Patrick Hand / Space Mono  — the two design faces (vendored)
//   Noto Emoji                 — monochrome flat emoji (vendored); broad
//                                ranges only in the two body-text faces
//   Arial Unicode (system)     — ▲▼▴▾ ★ ⊘ ⌕ ✓ → (neither design face has them)
//   Geneva (system)            — Ᵽ U+2C63: no mono/hand face carries the coin
//                                glyph (same gap the archived GUI hit)
#include "nk_config.h"
#include "theme.h"

#include "../../vendor/sokol/sokol_app.h"
#include "../../vendor/sokol/sokol_gfx.h"
#include "../../vendor/sokol/util/sokol_nuklear.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../platform.h"

// ── Faces ────────────────────────────────────────────────────────────────────
enum { SRC_PH, SRC_SMR, SRC_SMB, SRC_COUNT };

#define M_SYM   1u   // Arial Unicode symbols
#define M_COIN  2u   // Geneva Ᵽ
#define M_UIEMO 4u   // Noto: just the chrome emoji (⛏⛓✉📌🔥🌱🔇🔍)
#define M_BROAD 8u   // Noto: broad emoji ranges (body text)

// Logical sizes. The F_* names keep the DESIGN's px roles (what the canvas
// called 9/10/11…), but the small tiers bake bigger — the subtext floor is
// 12: metadata must be legible, hierarchy below 13 is carried by color
// (ghost/dim), not size.
static const struct { unsigned char src; float size; unsigned merges; } FACE[F_COUNT] = {
    [F_PH22]  = { SRC_PH, 22, M_SYM | M_COIN | M_UIEMO },
    [F_PH18]  = { SRC_PH, 18, M_SYM | M_COIN | M_BROAD },
    [F_PH16]  = { SRC_PH, 16, M_SYM | M_COIN | M_BROAD },
    [F_PH14]  = { SRC_PH, 14, M_SYM | M_COIN | M_UIEMO },
    [F_PH12]  = { SRC_PH, 13, M_SYM | M_COIN | M_UIEMO },
    [F_SM26]  = { SRC_SMR, 26, M_SYM | M_COIN | M_UIEMO },
    [F_SM22]  = { SRC_SMR, 22, M_SYM | M_COIN | M_UIEMO },
    [F_SM16]  = { SRC_SMR, 16, M_SYM | M_COIN | M_UIEMO },
    [F_SM14]  = { SRC_SMR, 14, M_SYM | M_COIN | M_UIEMO },
    [F_SM13]  = { SRC_SMR, 13, M_SYM | M_COIN | M_UIEMO },
    [F_SM11]  = { SRC_SMR, 13, M_SYM | M_COIN | M_UIEMO },
    [F_SM10]  = { SRC_SMR, 13, M_SYM | M_COIN | M_UIEMO },
    [F_SM9]   = { SRC_SMR, 12, M_SYM | M_COIN | M_UIEMO },
    [F_SMB10] = { SRC_SMB, 13, M_SYM | M_COIN | M_UIEMO },
    [F_SMB9]  = { SRC_SMB, 12, M_SYM | M_COIN | M_UIEMO },
};

// Base text ranges. The coin glyph is deliberately NOT here — it merges from
// Geneva; overlapping ranges would pack a .notdef box that shadows the merge.
static const nk_rune R_TEXT[] = {
    0x0020, 0x00FF,   // ASCII + Latin-1 (Ð lives here)
    0x2013, 0x2026,   // – — quotes …
    0x2039, 0x203A,   // ‹ ›
    0,
};
static const nk_rune R_SYM[] = {
    0x2192, 0x2192,   // →
    0x2298, 0x2298,   // ⊘
    0x2315, 0x2315,   // ⌕
    0x25B0, 0x25BF,   // ▲ ▴ ▼ ▾ block
    0x2605, 0x2605,   // ★
    0x2713, 0x2713,   // ✓
    0,
};
static const nk_rune R_COIN[]  = { 0x2C63, 0x2C63, 0 };
static const nk_rune R_UIEMO[] = {
    0x26CF, 0x26CF,   // ⛏
    0x26D3, 0x26D3,   // ⛓
    0x2709, 0x2709,   // ✉
    0x1F331, 0x1F331, // 🌱
    0x1F4CC, 0x1F4CC, // 📌
    0x1F507, 0x1F507, // 🔇
    0x1F50D, 0x1F50D, // 🔍
    0x1F525, 0x1F525, // 🔥
    0,
};
static const nk_rune R_BROAD[] = {
    0x2600, 0x27BF,   // misc symbols + dingbats (⛏⛓✉ included)
    0x2B00, 0x2BFF,   // ⭐ etc
    0x1F300, 0x1F5FF,
    0x1F600, 0x1F64F,
    0x1F680, 0x1F6FF,
    0x1F900, 0x1F9FF,
    0x1FA70, 0x1FAFF,
    0,
};

static struct {
    struct nk_font_atlas atlas;
    struct nk_font *font[F_COUNT];
    sg_image img;
    sg_view view;
    sg_sampler smp;
    snk_image_t snk_img;
    float dpi;
    int ready;
} T;

// vendored file → bundle Resources, then the dev tree (cmake defines it)
static const char *vendored(const char *name, char *buf, size_t cap) {
    if (platform_resource_path(name, buf, cap)) return buf;
#ifdef SHIB_DEV_FONT_DIR
    snprintf(buf, cap, "%s/%s", SHIB_DEV_FONT_DIR, name);
    if (access(buf, R_OK) == 0) return buf;
#endif
    fprintf(stderr, "theme: font %s not found (run scripts/fetch_vendors.sh)\n", name);
    return NULL;
}

static const char *system_font(const char *a, const char *b) {
    if (a && access(a, R_OK) == 0) return a;
    if (b && access(b, R_OK) == 0) return b;
    return NULL;
}

// The vendored nuklear's merge_mode extends `atlas->fonts` — the list HEAD
// (first font ever added), not the most recent one. Swapping the head to the
// target face around the call routes the merge where we want it; the merge
// path reads the head pointer only (never the list links), so this is safe.
static void merge_into(struct nk_font *target, const char *path, float px,
                       const nk_rune *range) {
    if (!path || !target) return;
    struct nk_font_config c = nk_font_config(px);
    c.range = range;
    c.merge_mode = nk_true;
    c.oversample_h = 1; c.oversample_v = 1;
    struct nk_font *head = T.atlas.fonts;
    T.atlas.fonts = target;
    nk_font_atlas_add_from_file(&T.atlas, path, px, &c);
    T.atlas.fonts = head;
}

void theme_init(struct nk_context *ctx, float dpi_scale) {
    char b0[1024], b1[1024], b2[1024], b3[1024];
    const char *ph  = vendored("PatrickHand-Regular.ttf", b0, sizeof b0);
    const char *smr = vendored("SpaceMono-Regular.ttf",   b1, sizeof b1);
    const char *smb = vendored("SpaceMono-Bold.ttf",      b2, sizeof b2);
    const char *emo = vendored("NotoEmoji-Regular.ttf",   b3, sizeof b3);
#ifdef _WIN32
    const char *sym  = system_font("C:/Windows/Fonts/seguisym.ttf",   // Segoe UI Symbol
                                   "C:/Windows/Fonts/arial.ttf");
    const char *coin = system_font("C:/Windows/Fonts/arial.ttf",      // Ᵽ U+2C63
                                   "C:/Windows/Fonts/segoeui.ttf");
#else
    const char *sym  = system_font("/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
                                   "/Library/Fonts/Arial Unicode.ttf");
    const char *coin = system_font("/System/Library/Fonts/Geneva.ttf",
                                   "/System/Library/Fonts/Supplemental/Arial.ttf");
#endif
    const char *src[SRC_COUNT] = {
        ph  ? ph  : (smr ? smr : smb),           // hand face falls back to mono
        smr ? smr : (smb ? smb : ph),
        smb ? smb : (smr ? smr : ph),
    };

    T.dpi = dpi_scale > 0 ? dpi_scale : 1.0f;
    nk_font_atlas_init_default(&T.atlas);
    nk_font_atlas_begin(&T.atlas);

    for (int i = 0; i < F_COUNT; i++) {
        float px = FACE[i].size * T.dpi;
        struct nk_font_config c = nk_font_config(px);
        c.range = R_TEXT;
        c.oversample_h = 1; c.oversample_v = 1;
        if (src[FACE[i].src])
            T.font[i] = nk_font_atlas_add_from_file(&T.atlas, src[FACE[i].src], px, &c);
        if (!T.font[i])
            T.font[i] = nk_font_atlas_add_default(&T.atlas, px, &c);
        if (FACE[i].merges & M_SYM)   merge_into(T.font[i], sym,  px, R_SYM);
        if (FACE[i].merges & M_COIN)  merge_into(T.font[i], coin, px, R_COIN);
        if (FACE[i].merges & M_UIEMO) merge_into(T.font[i], emo,  px, R_UIEMO);
        if (FACE[i].merges & M_BROAD) merge_into(T.font[i], emo,  px, R_BROAD);
    }

    int w = 0, h = 0;
    const void *pixels = nk_font_atlas_bake(&T.atlas, &w, &h, NK_FONT_ATLAS_RGBA32);
    T.img = sg_make_image(&(sg_image_desc){
        .width = w, .height = h,
        .pixel_format = SG_PIXELFORMAT_RGBA8,
        .data.mip_levels[0] = { .ptr = pixels, .size = (size_t)w * (size_t)h * 4 },
        .label = "pepenet-font-atlas",
    });
    T.view = sg_make_view(&(sg_view_desc){ .texture.image = T.img, .label = "font-atlas-view" });
    T.smp = sg_make_sampler(&(sg_sampler_desc){
        .min_filter = SG_FILTER_LINEAR, .mag_filter = SG_FILTER_LINEAR,
        .label = "font-atlas-smp",
    });
    T.snk_img = snk_make_image(&(snk_image_desc_t){ .texture_view = T.view, .sampler = T.smp });
    nk_font_atlas_end(&T.atlas, snk_nkhandle(T.snk_img), NULL);
    nk_font_atlas_cleanup(&T.atlas);

    // logical-point handles: layout in points, texels 1:1 at render
    for (int i = 0; i < F_COUNT; i++)
        if (T.font[i]) T.font[i]->handle.height = FACE[i].size;

    // ── nuklear style: the app is canvas-drawn; style only what nk widgets we
    //    actually use (edit fields, window chrome). Zero padding everywhere —
    //    all spacing is explicit.
    struct nk_color table[NK_COLOR_COUNT];
    nk_style_default(ctx);
    for (int i = 0; i < NK_COLOR_COUNT; i++) table[i] = C_BG;
    table[NK_COLOR_TEXT] = C_TEXT;
    table[NK_COLOR_WINDOW] = C_BG;
    table[NK_COLOR_EDIT] = C_INPUT;
    table[NK_COLOR_EDIT_CURSOR] = C_ACCENT;
    table[NK_COLOR_BORDER] = C_BORDER;
    nk_style_from_table(ctx, table);
    ctx->style.window.padding = nk_vec2(0, 0);
    ctx->style.window.group_padding = nk_vec2(0, 0);
    ctx->style.window.spacing = nk_vec2(0, 0);
    ctx->style.window.border = 0;
    ctx->style.window.scrollbar_size = nk_vec2(0, 0);
    ctx->style.edit.normal = nk_style_item_color(C_INPUT);
    ctx->style.edit.hover  = nk_style_item_color(C_INPUT);
    ctx->style.edit.active = nk_style_item_color(C_INPUT);
    ctx->style.edit.border_color = C_BORDER;
    ctx->style.edit.border = 1.0f;
    ctx->style.edit.rounding = 8.0f;
    ctx->style.edit.padding = nk_vec2(12, 9);
    ctx->style.edit.cursor_size = 1.0f;
    ctx->style.edit.cursor_normal = C_ACCENT;
    ctx->style.edit.cursor_hover = C_ACCENT;
    ctx->style.edit.cursor_text_normal = C_BG;
    ctx->style.edit.cursor_text_hover = C_BG;
    ctx->style.edit.text_normal = C_TEXT;
    ctx->style.edit.text_hover = C_TEXT;
    ctx->style.edit.text_active = C_TEXT;
    ctx->style.edit.selected_normal = C_ACCENT;
    ctx->style.edit.selected_hover = C_ACCENT;
    ctx->style.edit.selected_text_normal = C_ONFILL;
    ctx->style.edit.selected_text_hover = C_ONFILL;

    nk_style_set_font(ctx, &T.font[F_PH18]->handle);
    T.ready = 1;
}

struct nk_font *theme_font(ThemeFont f) { return T.font[f]; }
const struct nk_user_font *theme_uf(ThemeFont f) { return &T.font[f]->handle; }
float theme_lineh(ThemeFont f) { return T.font[f] ? T.font[f]->handle.height : 0; }

struct nk_color theme_fade_step(int step) {
    switch (step <= 0 ? 0 : (step >= 3 ? 3 : step)) {
        case 0:  return C_TEXT;
        case 1:  return C_DIM;
        case 2:  return C_FADE3;
        default: return C_GHOST;
    }
}
