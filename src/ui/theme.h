// theme.h — the PepeNet visual system (design/screens.html §1a).
//
// Swamp dark, flat only: solid fills, 1px borders, radii 6/10, spacing
// 4/8/12/16/24. Two typefaces with a hard rule: Patrick Hand is the voice
// (titles, body text, buttons); Space Mono is the truth — anything a user
// could lose money misreading (amounts, addresses, hashes, countdowns, byte
// counts) is ALWAYS Space Mono. Patrick Hand never touches a number that
// matters.
//
// The raw hex values live in appconf.h (the single instance-config file);
// this header only turns them into nk_color macros.
#ifndef SHIB_THEME_H
#define SHIB_THEME_H

#include <stddef.h>
#include "../appconf.h"

struct nk_context;
struct nk_font;
struct nk_color;

// ── Palette (appconf.h values) ───────────────────────────────────────────────
#define HEXC(x) nk_rgb(((x) >> 16) & 0xFF, ((x) >> 8) & 0xFF, (x) & 0xFF)
#define HEXA(x, a) nk_rgba(((x) >> 16) & 0xFF, ((x) >> 8) & 0xFF, (x) & 0xFF, (a))

#define C_BG      HEXC(TH_BG)      // window background
#define C_FOOTER  HEXC(TH_FOOTER)  // status-footer strip
#define C_PANEL   HEXC(TH_PANEL)   // raised cards, dialogs, menus
#define C_INPUT   HEXC(TH_INPUT)   // inputs; hover = one step up from panel
#define C_PRESS   HEXC(TH_PRESS)   // pressed step above C_INPUT
#define C_BORDER  HEXC(TH_BORDER)  // standard 1px border
#define C_HAIR    HEXC(TH_HAIR)    // hairline row/section dividers
#define C_TEXT    HEXC(TH_TEXT)    // primary text (also the QR card cream)
#define C_DIM     HEXC(TH_DIM)     // secondary text
#define C_FADE3   HEXC(TH_FADE3)   // expiry fade step 3
#define C_GHOST   HEXC(TH_GHOST)   // faint text / expiry fade step 4
#define C_ACCENT  HEXC(TH_ACCENT)  // accent: money actions, active tab, links
#define C_GREEN   HEXC(TH_OK)      // olive: ok, owned, online, servable
#define C_RED     HEXC(TH_RED)     // red: danger, expiring, destructive
#define C_ONFILL  HEXC(TH_ONFILL)  // text on an accent/olive/red fill

// tinted status strips (§9d pin states): translucent fill + solid border
#define C_TINT_OK      HEXA(TH_OK, 26)
#define C_TINT_OK_BR   HEXC(TH_TINT_OK_BR)
#define C_TINT_ACC     HEXA(TH_ACCENT, 23)
#define C_TINT_ACC_BR  HEXC(TH_TINT_ACC_BR)
#define C_TINT_RED     HEXA(TH_RED, 26)
#define C_TINT_RED_BR  HEXC(TH_TINT_RED_BR)

// Expiry fade (§1a): 4 text steps as an ephemeral post nears its 42d death.
// step 0 = fresh … step 3 = about to fade out.
struct nk_color theme_fade_step(int step);          // 0..3 → TEXT/DIM/FADE3/GHOST

// ── Type ─────────────────────────────────────────────────────────────────────
// Logical (point) sizes; the atlas bakes them at the display scale so retina
// glyphs are 1:1 texels. PH = Patrick Hand, SM = Space Mono, SMB = Space Mono
// Bold (badges + tiny letter-spaced labels).
typedef enum {
    F_PH22,          // section & dialog titles
    F_PH18,          // body text, composer (broad emoji merged here)
    F_PH16,          // authors, menu items, buttons (broad emoji merged here)
    F_PH14,          // small buttons, chips
    F_PH12,          // tiny hints ("edit", "no name")
    F_SM26,          // countdowns, amount input
    F_SM22,          // balance dropdown amount
    F_SM16,          // room titles, dialog inputs
    F_SM14,          // amounts, prices
    F_SM13,          // names, addresses
    F_SM11,          // meta rows (fees, rent rate)
    F_SM10,          // timestamps, sub-lines
    F_SM9,           // 8.5–9.5px letter-spaced section headers
    F_SMB10,         // ⛏ ENGRAVED, unread pills
    F_SMB9,          // state badges (OWNED / LISTED / …)
    F_COUNT
} ThemeFont;

// Build the atlas + push the nuklear style table. Call once after snk_setup
// (needs sokol-gfx alive). dpi_scale = sapp_dpi_scale().
void theme_init(struct nk_context *ctx, float dpi_scale);

struct nk_font *theme_font(ThemeFont f);
const struct nk_user_font *theme_uf(ThemeFont f);   // handle for draw calls
float theme_lineh(ThemeFont f);                     // logical line height

#endif
