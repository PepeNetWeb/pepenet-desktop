// Sokol + Nuklear single-translation-unit implementations — Windows build.
// Mirrors sokol_impl.m: same three IMPL defines, D3D11 instead of Metal
// (SOKOL_D3D11 is set by CMake via compile definitions).
//
// platform_style_window here keeps the NATIVE titlebar (unlike the mac's
// hidden-titlebar + drawn-bar trick): the drawn 38px brand strip reads as an
// in-app header under it. The native bar is themed to the design's swamp-dark
// palette via DWM (dark mode + caption color, Win11; harmless no-ops on 10),
// and a window subclass enforces the design's minimum content size.

#define SOKOL_IMPL
// SOKOL_D3D11 comes from CMake
#include "../vendor/sokol/sokol_app.h"
#include "../vendor/sokol/sokol_gfx.h"
#include "../vendor/sokol/sokol_glue.h"
#include "../vendor/sokol/sokol_log.h"

#define NK_IMPLEMENTATION
#include "ui/nk_config.h"          // the ONE nuklear flag set (ui/nk_config.h)

#define SOKOL_NUKLEAR_IMPL
#include "../vendor/sokol/util/sokol_nuklear.h"

#include <windows.h>
#include <commctrl.h>
#include <dwmapi.h>

#include "appconf.h"

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif
#ifndef DWMWA_CAPTION_COLOR
#define DWMWA_CAPTION_COLOR 35
#endif

static int g_min_w, g_min_h;   // window (outer) minimum, from the design's content min

static LRESULT CALLBACK style_subclass(HWND w, UINT msg, WPARAM wp, LPARAM lp,
                                       UINT_PTR id, DWORD_PTR data) {
    (void)id; (void)data;
    if (msg == WM_GETMINMAXINFO && g_min_w > 0) {
        MINMAXINFO *mi = (MINMAXINFO *)lp;
        mi->ptMinTrackSize.x = g_min_w;
        mi->ptMinTrackSize.y = g_min_h;
        return 0;
    }
    return DefSubclassProc(w, msg, wp, lp);
}

// ui_scale converts the design's logical px to window points (main.c UI_SCALE).
void platform_style_window(float ui_scale) {
    HWND w = (HWND)sapp_win32_get_hwnd();
    if (!w) return;

    // dark titlebar + caption tinted to the design background (Win11; the
    // attributes are simply ignored where unsupported)
    BOOL dark = TRUE;
    DwmSetWindowAttribute(w, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof dark);
    COLORREF cap = RGB((TH_BG >> 16) & 0xFF, (TH_BG >> 8) & 0xFF, TH_BG & 0xFF);
    DwmSetWindowAttribute(w, DWMWA_CAPTION_COLOR, &cap, sizeof cap);

    // design minimum 520×640 logical, scaled by dpi × UI_SCALE like the mac's
    // setContentMinSize — converted from client to outer-window size
    float dpi = sapp_dpi_scale();
    RECT r = { 0, 0, (LONG)(520.0f * ui_scale * dpi), (LONG)(640.0f * ui_scale * dpi) };
    DWORD style = (DWORD)GetWindowLongPtrW(w, GWL_STYLE);
    DWORD exstyle = (DWORD)GetWindowLongPtrW(w, GWL_EXSTYLE);
    AdjustWindowRectEx(&r, style, FALSE, exstyle);
    g_min_w = r.right - r.left;
    g_min_h = r.bottom - r.top;
    SetWindowSubclass(w, style_subclass, 0xD06F, 0);
}
