// Sokol + Nuklear single-translation-unit implementations (desktop client).
// Must be compiled as Objective-C (.m) on macOS because sokol_app/sokol_gfx
// pull in Metal/Cocoa headers which require ObjC. Mirrors clients/gui's copy;
// only the include paths differ (clients/desktop is one level deeper).

#define SOKOL_IMPL
// SOKOL_METAL is set by CMake via compile definitions
#include "../vendor/sokol/sokol_app.h"
#include "../vendor/sokol/sokol_gfx.h"
#include "../vendor/sokol/sokol_glue.h"
#include "../vendor/sokol/sokol_log.h"

#define NK_IMPLEMENTATION
#include "ui/nk_config.h"          // the ONE nuklear flag set (ui/nk_config.h)

#define SOKOL_NUKLEAR_IMPL
#include "../vendor/sokol/util/sokol_nuklear.h"

#import <Cocoa/Cocoa.h>

// ── Window setup (mockup titlebar: full-size content, we draw the 38px bar;
//    native traffic lights float over it) ───────────────────────────────────
// ui_scale converts the design's logical px to window points (main.c UI_SCALE).
void platform_style_window(float ui_scale) {
    NSWindow *win = (NSWindow *)(uintptr_t)sapp_macos_get_window();
    if (!win) return;
    win.styleMask |= NSWindowStyleMaskFullSizeContentView | NSWindowStyleMaskResizable;
    win.titlebarAppearsTransparent = YES;
    win.titleVisibility = NSWindowTitleHidden;
    [win setContentMinSize:NSMakeSize(520 * ui_scale, 640 * ui_scale)];  // design minimum
    win.backgroundColor = [NSColor colorWithSRGBRed:0x1A / 255.0
                                              green:0x19 / 255.0
                                               blue:0x16 / 255.0
                                              alpha:1.0];

    // The Metal view fills the whole window (full-size content), so AppKit's
    // titlebar drag region never sees the mouse — the window can't be moved.
    // Reinstate dragging for our drawn 38px bar: a mouse-down there that
    // doesn't land on a native control (traffic lights hit-test to their own
    // NSButtons) starts a window drag; double-click zooms like a real titlebar.
    CGFloat bar = 38 * ui_scale;
    [NSEvent addLocalMonitorForEventsMatchingMask:NSEventMaskLeftMouseDown
                                          handler:^NSEvent *(NSEvent *e) {
        if (e.window != win) return e;
        NSView *cv = win.contentView;
        NSPoint p = [cv convertPoint:e.locationInWindow fromView:nil];
        CGFloat from_top = cv.isFlipped ? p.y : NSHeight(cv.bounds) - p.y;
        if (from_top < 0 || from_top > bar) return e;
        NSView *hit = [cv.superview hitTest:e.locationInWindow];
        if (hit != cv) return e;                        // a native control
        if (e.clickCount == 2) [win performZoom:nil];
        else [win performWindowDragWithEvent:e];
        return nil;                                     // the bar is not canvas
    }];
}
