// tray_linux.c — StatusNotifierItem + the tray-resident lifecycle on Linux
// (mirrors tray.m / tray_win.c).
//
// Close HIDES the window and keeps every engine warm. The tray icon is the
// only real Quit. dbus is pumped from platform_window_visible (every frame)
// so clicks stay live; tray_update() only refreshes the tooltip/status rows.
#if defined(__linux__) || defined(__unix__)
#ifndef _WIN32
#ifndef __APPLE__

#include "appconf.h"
#include "platform.h"
#include "webproxy.h"
#include "dnsnet.h"
#include "model.h"
#include "ui/strings.h"

#include "../vendor/sokol/sokol_app.h"

#include <X11/Xlib.h>
#include <dbus/dbus.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void sapp_request_quit(void);
void fmt_thousands(char *out, size_t cap, int64_t n);
void fmt_amount(char *out, size_t cap, int64_t koinu);

unsigned char *stbi_load(char const *filename, int *x, int *y, int *comp, int req);
void stbi_image_free(void *retval);

#define TRAY_ROWS 5
#define SNI_PATH  "/StatusNotifierItem"
#define MENU_PATH "/MenuBar"

static DBusConnection *g_bus;
static int g_visible = 1;
static int g_really_quit;
static int g_registered;
static unsigned g_rev = 1;
static uint32_t *g_argb;          // IconPixmap payload (network-order ARGB)
static int g_iw, g_ih;

static const char *const WATCHERS[] = {
    "org.kde.StatusNotifierWatcher",
    "org.freedesktop.StatusNotifierWatcher",
    "org.ayatana.StatusNotifierWatcher",
    NULL
};

static void status_lines(char out[TRAY_ROWS][64]) {
    if (M.web.running && M.dns.resolver_running)
        snprintf(out[0], 64, "%s", TR(S_TRAY_WEB_ON));
    else
        snprintf(out[0], 64, "%s", TR(S_TRAY_WEB_OFF));
    if (M.unreachable)
        snprintf(out[1], 64, "%s", TR(S_TRAY_CHAIN_UNREACH));
    else if (!M.running)
        snprintf(out[1], 64, "%s", TR(S_TRAY_CHAIN_STARTING));
    else {
        char hb[32];
        fmt_thousands(hb, sizeof hb, M.height);
        snprintf(out[1], 64, TR(S_TRAY_CHAIN_FMT),
                 M.synced ? TR(S_SYNC_SYNCED) : TR(S_SYNC_SYNCING), hb);
    }
    char a[32];
    fmt_amount(a, sizeof a, model_fee_k());
    snprintf(out[2], 64, TR(S_TRAY_FEE_FMT), a);
    fmt_amount(a, sizeof a, M.year_cost);
    snprintf(out[3], 64, TR(S_TRAY_RENT_FMT), a);
    if (M.dns.running)
        snprintf(out[4], 64, TR(S_TRAY_MESH_FMT), M.dns.peers,
                 M.dns.peers == 1 ? "" : "s");
    else
        snprintf(out[4], 64, "%s", TR(S_TRAY_MESH_STARTING));
}

static Display *dpy(void) { return (Display *)sapp_x11_get_display(); }
static Window  xwin(void) { return (Window)(uintptr_t)sapp_x11_get_window(); }

static void show_window(void) {
    Display *d = dpy();
    Window w = xwin();
    if (d && w) {
        XMapRaised(d, w);
        XFlush(d);
    }
    g_visible = 1;
}

void tray_hide_window(void) {
    Display *d = dpy();
    Window w = xwin();
    if (d && w) {
        XUnmapWindow(d, w);
        XFlush(d);
    }
    g_visible = 0;
}

void tray_background_start(void) { tray_hide_window(); }

static void load_icon(void) {
    char path[600];
    if (!platform_resource_path(APP_TRAY_ICON, path, sizeof path)) {
#ifdef SHIB_DEV_TRAY_ICON
        snprintf(path, sizeof path, "%s", SHIB_DEV_TRAY_ICON);
#else
        return;
#endif
    }
    int w = 0, h = 0, n = 0;
    unsigned char *rgba = stbi_load(path, &w, &h, &n, 4);
    if (!rgba || w <= 0 || h <= 0) { if (rgba) stbi_image_free(rgba); return; }
    g_argb = (uint32_t *)malloc((size_t)w * (size_t)h * 4);
    if (!g_argb) { stbi_image_free(rgba); return; }
    for (int i = 0; i < w * h; i++) {
        unsigned r = rgba[i * 4 + 0], g = rgba[i * 4 + 1];
        unsigned b = rgba[i * 4 + 2], a = rgba[i * 4 + 3];
        g_argb[i] = ((uint32_t)a << 24) | ((uint32_t)r << 16) |
                    ((uint32_t)g << 8)  | (uint32_t)b;
        g_argb[i] = __builtin_bswap32(g_argb[i]); /* network byte order */
    }
    g_iw = w; g_ih = h;
    stbi_image_free(rgba);
}

static void append_s(DBusMessageIter *var, const char *s) {
    DBusMessageIter v;
    dbus_message_iter_open_container(var, DBUS_TYPE_VARIANT, "s", &v);
    dbus_message_iter_append_basic(&v, DBUS_TYPE_STRING, &s);
    dbus_message_iter_close_container(var, &v);
}
static void append_b(DBusMessageIter *var, dbus_bool_t b) {
    DBusMessageIter v;
    dbus_message_iter_open_container(var, DBUS_TYPE_VARIANT, "b", &v);
    dbus_message_iter_append_basic(&v, DBUS_TYPE_BOOLEAN, &b);
    dbus_message_iter_close_container(var, &v);
}
static void append_u(DBusMessageIter *var, dbus_uint32_t u) {
    DBusMessageIter v;
    dbus_message_iter_open_container(var, DBUS_TYPE_VARIANT, "u", &v);
    dbus_message_iter_append_basic(&v, DBUS_TYPE_UINT32, &u);
    dbus_message_iter_close_container(var, &v);
}
static void append_o(DBusMessageIter *var, const char *o) {
    DBusMessageIter v;
    dbus_message_iter_open_container(var, DBUS_TYPE_VARIANT, "o", &v);
    dbus_message_iter_append_basic(&v, DBUS_TYPE_OBJECT_PATH, &o);
    dbus_message_iter_close_container(var, &v);
}

static void append_icon_pixmap(DBusMessageIter *outer) {
    DBusMessageIter var, arr, st, bytes;
    dbus_message_iter_open_container(outer, DBUS_TYPE_VARIANT, "a(iiay)", &var);
    dbus_message_iter_open_container(&var, DBUS_TYPE_ARRAY, "(iiay)", &arr);
    if (g_argb && g_iw > 0) {
        dbus_message_iter_open_container(&arr, DBUS_TYPE_STRUCT, NULL, &st);
        dbus_int32_t w = g_iw, h = g_ih;
        dbus_message_iter_append_basic(&st, DBUS_TYPE_INT32, &w);
        dbus_message_iter_append_basic(&st, DBUS_TYPE_INT32, &h);
        int nbytes = g_iw * g_ih * 4;
        dbus_message_iter_open_container(&st, DBUS_TYPE_ARRAY, "y", &bytes);
        const unsigned char *p = (const unsigned char *)g_argb;
        dbus_message_iter_append_fixed_array(&bytes, DBUS_TYPE_BYTE, &p, nbytes);
        dbus_message_iter_close_container(&st, &bytes);
        dbus_message_iter_close_container(&arr, &st);
    }
    dbus_message_iter_close_container(&var, &arr);
    dbus_message_iter_close_container(outer, &var);
}

static int prop_get(DBusMessage *m, DBusMessage *r) {
    const char *iface = NULL, *prop = NULL;
    if (!dbus_message_get_args(m, NULL, DBUS_TYPE_STRING, &iface,
                               DBUS_TYPE_STRING, &prop, DBUS_TYPE_INVALID))
        return 0;
    DBusMessageIter it;
    dbus_message_iter_init_append(r, &it);
    if (!strcmp(prop, "Category"))      append_s(&it, "ApplicationStatus");
    else if (!strcmp(prop, "Id"))       append_s(&it, "pepenet");
    else if (!strcmp(prop, "Title"))    append_s(&it, APP_NAME);
    else if (!strcmp(prop, "Status"))   append_s(&it, "Active");
    else if (!strcmp(prop, "IconName")) append_s(&it, "pepenet");
    else if (!strcmp(prop, "Menu"))     append_o(&it, MENU_PATH);
    else if (!strcmp(prop, "ItemIsMenu")) {
        dbus_bool_t b = FALSE; append_b(&it, b);
    } else if (!strcmp(prop, "WindowId")) {
        dbus_uint32_t u = (dbus_uint32_t)xwin(); append_u(&it, u);
    } else if (!strcmp(prop, "IconPixmap")) {
        append_icon_pixmap(&it);
    } else {
        return 0;
    }
    return 1;
}

static void dict_put_s(DBusMessageIter *arr, const char *k, const char *v) {
    DBusMessageIter e, var;
    dbus_message_iter_open_container(arr, DBUS_TYPE_DICT_ENTRY, NULL, &e);
    dbus_message_iter_append_basic(&e, DBUS_TYPE_STRING, &k);
    dbus_message_iter_open_container(&e, DBUS_TYPE_VARIANT, "s", &var);
    dbus_message_iter_append_basic(&var, DBUS_TYPE_STRING, &v);
    dbus_message_iter_close_container(&e, &var);
    dbus_message_iter_close_container(arr, &e);
}
static void dict_put_b(DBusMessageIter *arr, const char *k, dbus_bool_t v) {
    DBusMessageIter e, var;
    dbus_message_iter_open_container(arr, DBUS_TYPE_DICT_ENTRY, NULL, &e);
    dbus_message_iter_append_basic(&e, DBUS_TYPE_STRING, &k);
    dbus_message_iter_open_container(&e, DBUS_TYPE_VARIANT, "b", &var);
    dbus_message_iter_append_basic(&var, DBUS_TYPE_BOOLEAN, &v);
    dbus_message_iter_close_container(&e, &var);
    dbus_message_iter_close_container(arr, &e);
}

static void menu_item(DBusMessageIter *children, int id, const char *label, int enabled) {
    DBusMessageIter var, st, props, kids;
    dbus_message_iter_open_container(children, DBUS_TYPE_VARIANT, "(ia{sv}av)", &var);
    dbus_message_iter_open_container(&var, DBUS_TYPE_STRUCT, NULL, &st);
    dbus_int32_t iid = id;
    dbus_message_iter_append_basic(&st, DBUS_TYPE_INT32, &iid);
    dbus_message_iter_open_container(&st, DBUS_TYPE_ARRAY, "{sv}", &props);
    if (label) dict_put_s(&props, "label", label);
    else       dict_put_s(&props, "type", "separator");
    if (label && !enabled) {
        dbus_bool_t f = FALSE;
        dict_put_b(&props, "enabled", f);
    }
    dbus_message_iter_close_container(&st, &props);
    dbus_message_iter_open_container(&st, DBUS_TYPE_ARRAY, "v", &kids);
    dbus_message_iter_close_container(&st, &kids);
    dbus_message_iter_close_container(&var, &st);
    dbus_message_iter_close_container(children, &var);
}

static void menu_layout(DBusMessage *r) {
    char lines[TRAY_ROWS][64];
    status_lines(lines);
    DBusMessageIter it, st, props, kids;
    dbus_uint32_t rev = g_rev;
    dbus_message_iter_init_append(r, &it);
    dbus_message_iter_append_basic(&it, DBUS_TYPE_UINT32, &rev);
    dbus_message_iter_open_container(&it, DBUS_TYPE_STRUCT, NULL, &st);
    dbus_int32_t root = 0;
    dbus_message_iter_append_basic(&st, DBUS_TYPE_INT32, &root);
    dbus_message_iter_open_container(&st, DBUS_TYPE_ARRAY, "{sv}", &props);
    dict_put_s(&props, "children-display", "submenu");
    dbus_message_iter_close_container(&st, &props);
    dbus_message_iter_open_container(&st, DBUS_TYPE_ARRAY, "v", &kids);
    menu_item(&kids, 1, TR(S_TRAY_OPEN), 1);
    menu_item(&kids, 2, NULL, 1);
    for (int i = 0; i < TRAY_ROWS; i++)
        menu_item(&kids, 3 + i, lines[i], 0);
    menu_item(&kids, 8, NULL, 1);
    menu_item(&kids, 9, TR(S_TRAY_QUIT), 1);
    dbus_message_iter_close_container(&st, &kids);
    dbus_message_iter_close_container(&it, &st);
}

static void register_sni(void) {
    if (!g_bus || g_registered) return;
    const char *name = dbus_bus_get_unique_name(g_bus);
    if (!name) return;
    for (int i = 0; WATCHERS[i]; i++) {
        DBusMessage *m = dbus_message_new_method_call(
            WATCHERS[i], "/StatusNotifierWatcher",
            "org.kde.StatusNotifierWatcher", "RegisterStatusNotifierItem");
        if (!m) continue;
        dbus_message_append_args(m, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID);
        DBusMessage *r = dbus_connection_send_with_reply_and_block(g_bus, m, 500, NULL);
        dbus_message_unref(m);
        if (r) {
            dbus_message_unref(r);
            g_registered = 1;
            return;
        }
        /* ayatana uses the same method on its own iface name */
        m = dbus_message_new_method_call(
            WATCHERS[i], "/StatusNotifierWatcher",
            WATCHERS[i], "RegisterStatusNotifierItem");
        if (!m) continue;
        dbus_message_append_args(m, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID);
        r = dbus_connection_send_with_reply_and_block(g_bus, m, 500, NULL);
        dbus_message_unref(m);
        if (r) { dbus_message_unref(r); g_registered = 1; return; }
    }
}

static DBusHandlerResult on_msg(DBusConnection *c, DBusMessage *m, void *data) {
    (void)data;
    const char *path = dbus_message_get_path(m);
    if (!path) return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    if (!strcmp(path, SNI_PATH) &&
        dbus_message_is_method_call(m, "org.freedesktop.DBus.Properties", "Get")) {
        DBusMessage *r = dbus_message_new_method_return(m);
        if (r && prop_get(m, r)) dbus_connection_send(c, r, NULL);
        if (r) dbus_message_unref(r);
        return DBUS_HANDLER_RESULT_HANDLED;
    }
    if (!strcmp(path, SNI_PATH) &&
        dbus_message_is_method_call(m, "org.freedesktop.DBus.Properties", "GetAll")) {
        DBusMessage *r = dbus_message_new_method_return(m);
        DBusMessageIter it, arr, e;
        dbus_bool_t no = FALSE;
        dbus_uint32_t wid = (dbus_uint32_t)xwin();
        dbus_message_iter_init_append(r, &it);
        dbus_message_iter_open_container(&it, DBUS_TYPE_ARRAY, "{sv}", &arr);
        #define PUT_S(k, v) do { const char *_k = (k); \
            dbus_message_iter_open_container(&arr, DBUS_TYPE_DICT_ENTRY, NULL, &e); \
            dbus_message_iter_append_basic(&e, DBUS_TYPE_STRING, &_k); \
            append_s(&e, (v)); \
            dbus_message_iter_close_container(&arr, &e); } while (0)
        PUT_S("Category", "ApplicationStatus");
        PUT_S("Id", "pepenet");
        PUT_S("Title", APP_NAME);
        PUT_S("Status", "Active");
        PUT_S("IconName", "pepenet");
        #undef PUT_S
        { const char *k = "Menu";
          dbus_message_iter_open_container(&arr, DBUS_TYPE_DICT_ENTRY, NULL, &e);
          dbus_message_iter_append_basic(&e, DBUS_TYPE_STRING, &k);
          append_o(&e, MENU_PATH);
          dbus_message_iter_close_container(&arr, &e); }
        { const char *k = "ItemIsMenu";
          dbus_message_iter_open_container(&arr, DBUS_TYPE_DICT_ENTRY, NULL, &e);
          dbus_message_iter_append_basic(&e, DBUS_TYPE_STRING, &k);
          append_b(&e, no);
          dbus_message_iter_close_container(&arr, &e); }
        { const char *k = "WindowId";
          dbus_message_iter_open_container(&arr, DBUS_TYPE_DICT_ENTRY, NULL, &e);
          dbus_message_iter_append_basic(&e, DBUS_TYPE_STRING, &k);
          append_u(&e, wid);
          dbus_message_iter_close_container(&arr, &e); }
        { const char *k = "IconPixmap";
          dbus_message_iter_open_container(&arr, DBUS_TYPE_DICT_ENTRY, NULL, &e);
          dbus_message_iter_append_basic(&e, DBUS_TYPE_STRING, &k);
          append_icon_pixmap(&e);
          dbus_message_iter_close_container(&arr, &e); }
        dbus_message_iter_close_container(&it, &arr);
        dbus_connection_send(c, r, NULL);
        dbus_message_unref(r);
        return DBUS_HANDLER_RESULT_HANDLED;
    }
    if (!strcmp(path, SNI_PATH) &&
        (dbus_message_is_method_call(m, "org.kde.StatusNotifierItem", "Activate") ||
         dbus_message_is_method_call(m, "org.kde.StatusNotifierItem", "SecondaryActivate"))) {
        show_window();
        DBusMessage *r = dbus_message_new_method_return(m);
        if (r) { dbus_connection_send(c, r, NULL); dbus_message_unref(r); }
        return DBUS_HANDLER_RESULT_HANDLED;
    }
    if (!strcmp(path, SNI_PATH) &&
        dbus_message_is_method_call(m, "org.kde.StatusNotifierItem", "ContextMenu")) {
        /* menu is dbusmenu; still raise in case the host doesn't pop it */
        DBusMessage *r = dbus_message_new_method_return(m);
        if (r) { dbus_connection_send(c, r, NULL); dbus_message_unref(r); }
        return DBUS_HANDLER_RESULT_HANDLED;
    }
    if (!strcmp(path, MENU_PATH) &&
        dbus_message_is_method_call(m, "com.canonical.dbusmenu", "GetLayout")) {
        DBusMessage *r = dbus_message_new_method_return(m);
        if (r) { menu_layout(r); dbus_connection_send(c, r, NULL); dbus_message_unref(r); }
        return DBUS_HANDLER_RESULT_HANDLED;
    }
    if (!strcmp(path, MENU_PATH) &&
        dbus_message_is_method_call(m, "com.canonical.dbusmenu", "AboutToShow")) {
        g_rev++;
        DBusMessage *r = dbus_message_new_method_return(m);
        dbus_bool_t need = TRUE;
        if (r) {
            dbus_message_append_args(r, DBUS_TYPE_BOOLEAN, &need, DBUS_TYPE_INVALID);
            dbus_connection_send(c, r, NULL);
            dbus_message_unref(r);
        }
        return DBUS_HANDLER_RESULT_HANDLED;
    }
    if (!strcmp(path, MENU_PATH) &&
        dbus_message_is_method_call(m, "com.canonical.dbusmenu", "Event")) {
        dbus_int32_t id = 0;
        const char *ev = NULL;
        DBusMessageIter it;
        if (dbus_message_iter_init(m, &it) &&
            dbus_message_iter_get_arg_type(&it) == DBUS_TYPE_INT32) {
            dbus_message_iter_get_basic(&it, &id);
            dbus_message_iter_next(&it);
            if (dbus_message_iter_get_arg_type(&it) == DBUS_TYPE_STRING)
                dbus_message_iter_get_basic(&it, &ev);
        }
        if (ev && !strcmp(ev, "clicked")) {
            if (id == 1) show_window();
            else if (id == 9) { g_really_quit = 1; sapp_request_quit(); }
        }
        DBusMessage *r = dbus_message_new_method_return(m);
        if (r) { dbus_connection_send(c, r, NULL); dbus_message_unref(r); }
        return DBUS_HANDLER_RESULT_HANDLED;
    }
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void dbus_pump(void) {
    if (!g_bus) return;
    dbus_connection_read_write(g_bus, 0);
    while (dbus_connection_get_dispatch_status(g_bus) == DBUS_DISPATCH_DATA_REMAINS)
        dbus_connection_dispatch(g_bus);
    if (!g_registered) register_sni();
}

void tray_setup(void) {
    if (g_bus) return;
    DBusError err;
    dbus_error_init(&err);
    g_bus = dbus_bus_get(DBUS_BUS_SESSION, &err);
    if (!g_bus) { dbus_error_free(&err); return; }
    dbus_connection_set_exit_on_disconnect(g_bus, FALSE);
    dbus_bus_request_name(g_bus, "org.pepenet.StatusNotifierItem", 0, NULL);
    dbus_connection_add_filter(g_bus, on_msg, NULL, NULL);
    dbus_bus_add_match(g_bus,
        "type='method_call',path='" SNI_PATH "'", NULL);
    dbus_bus_add_match(g_bus,
        "type='method_call',path='" MENU_PATH "'", NULL);
    load_icon();
    register_sni();
    g_visible = 1;
}

void tray_update(void) {
    dbus_pump();
}

void tray_test_close(void) { tray_hide_window(); }
void tray_test_quit(void)  { g_really_quit = 1; sapp_request_quit(); }
void tray_test_dump(void) {
    char l[TRAY_ROWS][64];
    status_lines(l);
    for (int i = 0; i < TRAY_ROWS; i++) fprintf(stderr, "TRAYROW %s\n", l[i]);
}

int tray_quit_requested(void) {
    if (g_really_quit) return 1;
    tray_hide_window();
    return 0;
}

int platform_window_visible(void) {
    dbus_pump();
    return g_visible;
}

#endif
#endif
#endif
