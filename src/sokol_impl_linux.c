// Sokol + Nuklear single-translation-unit implementations — Linux build.
// Mirrors sokol_impl_win.c: same three IMPL defines, GLCORE instead of D3D11
// (SOKOL_GLCORE is set by CMake via compile definitions).
//
// platform_style_window keeps the NATIVE titlebar (like Windows, unlike the
// mac drawn-bar trick): the 38px brand strip reads as an in-app header under
// it. Min size is an XSizeHints PMinSize on the sokol X11 window.
#if defined(__linux__) || defined(__unix__)
#ifndef _WIN32
#ifndef __APPLE__

#define SOKOL_IMPL
#include "../vendor/sokol/sokol_app.h"
#include "../vendor/sokol/sokol_gfx.h"
#include "../vendor/sokol/sokol_glue.h"
#include "../vendor/sokol/sokol_log.h"

#define NK_IMPLEMENTATION
#include "ui/nk_config.h"

#define SOKOL_NUKLEAR_IMPL
#include "../vendor/sokol/util/sokol_nuklear.h"

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <string.h>

void platform_style_window(float ui_scale) {
    Display *dpy = (Display *)sapp_x11_get_display();
    Window w = (Window)(uintptr_t)sapp_x11_get_window();
    if (!dpy || !w) return;
    float dpi = sapp_dpi_scale();
    XSizeHints hints;
    memset(&hints, 0, sizeof hints);
    hints.flags = PMinSize;
    hints.min_width  = (int)(520.0f * ui_scale * dpi);
    hints.min_height = (int)(640.0f * ui_scale * dpi);
    XSetWMNormalHints(dpy, w, &hints);
    XFlush(dpy);
}

#endif
#endif
#endif
