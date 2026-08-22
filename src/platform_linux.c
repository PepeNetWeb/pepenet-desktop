// platform_linux.c — Linux implementation of the stateless platform.h
// primitives (paths, XDG config, executable location, bundled resources,
// launching, secret storage, XDG autostart). Windowing halves live with the
// code that owns the X11 Window: sokol_impl_linux.c (platform_style_window)
// and tray_linux.c (platform_window_visible). See platform.h.
#if defined(__linux__) || defined(__unix__)
#ifndef _WIN32
#ifndef __APPLE__

#define _GNU_SOURCE
#include "platform.h"
#include "appconf.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <libsecret/secret.h>

#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

extern char **environ;

// ── tiny helpers ─────────────────────────────────────────────────────────────
static int is_abs_path(const char *p) { return p && p[0] == '/'; }

static const char *home_dir(void) {
    const char *h = getenv("HOME");
    return (h && h[0]) ? h : ".";
}

static void xdg_config_dir(char *out, size_t cap) {
    const char *xdg = getenv("XDG_CONFIG_HOME");
    if (xdg && xdg[0] == '/')
        snprintf(out, cap, "%s/pepenet", xdg);
    else
        snprintf(out, cap, "%s/.config/pepenet", home_dir());
}

static void mkdir_p(const char *path) {
    char buf[600];
    snprintf(buf, sizeof buf, "%s", path);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/') continue;
        *p = 0;
        mkdir(buf, 0755);
        *p = '/';
    }
    mkdir(buf, 0755);
}

// ── persisted app config (XDG — lives OUTSIDE the data dir) ──────────────────
static void config_path(char *out, size_t cap) {
    char dir[500];
    xdg_config_dir(dir, sizeof dir);
    snprintf(out, cap, "%s/config", dir);
}

int platform_config_get(const char *key, char *out, size_t cap) {
    if (!key || !out || !cap) return 0;
    out[0] = 0;
    char path[600];
    config_path(path, sizeof path);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[700];
    size_t klen = strlen(key);
    int found = 0;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, key, klen) == 0 && line[klen] == '=') {
            char *v = line + klen + 1;
            v[strcspn(v, "\r\n")] = 0;
            snprintf(out, cap, "%s", v);
            found = out[0] != 0;
            break;
        }
    }
    fclose(f);
    return found;
}

int platform_config_set(const char *key, const char *val) {
    if (!key) return 0;
    char dir[500], path[600], tmp[620];
    xdg_config_dir(dir, sizeof dir);
    mkdir_p(dir);
    config_path(path, sizeof path);
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *in = fopen(path, "r");
    FILE *out = fopen(tmp, "w");
    if (!out) { if (in) fclose(in); return 0; }
    size_t klen = strlen(key);
    int replaced = 0;
    char line[700];
    if (in) {
        while (fgets(line, sizeof line, in)) {
            if (strncmp(line, key, klen) == 0 && line[klen] == '=') {
                replaced = 1;
                if (val && val[0]) fprintf(out, "%s=%s\n", key, val);
                continue;               // empty val = clear
            }
            fputs(line, out);
        }
        fclose(in);
    }
    if (!replaced && val && val[0]) fprintf(out, "%s=%s\n", key, val);
    fclose(out);
    return rename(tmp, path) == 0;
}

// ── filesystem locations ──────────────────────────────────────────────────────
const char *platform_data_dir(char *out, size_t cap) {
    char over[600];
    if (platform_config_get("data_dir", over, sizeof over) && is_abs_path(over)) {
        snprintf(out, cap, "%s", over);
    } else {
        snprintf(out, cap, "%s/.%s", home_dir(), APP_DATA_DIR);
    }
    mkdir(out, 0755);
    return out;
}

const char *platform_data_path(const char *name, char *out, size_t cap) {
    char dir[600];
    platform_data_dir(dir, sizeof dir);
    snprintf(out, cap, "%s/%s", dir, name);
    return out;
}

int platform_choose_directory(char *out, size_t cap) {
    if (!out || !cap) return 0;
    out[0] = 0;
    FILE *p = popen("zenity --file-selection --directory --title='Choose a data folder' 2>/dev/null", "r");
    if (!p) return 0;
    if (!fgets(out, (int)cap, p)) { pclose(p); out[0] = 0; return 0; }
    pclose(p);
    out[strcspn(out, "\r\n")] = 0;
    return out[0] == '/';
}

int platform_executable_path(char *out, size_t cap) {
    if (!out || !cap) return 0;
    ssize_t n = readlink("/proc/self/exe", out, cap - 1);
    if (n <= 0 || (size_t)n >= cap) { if (cap) out[0] = 0; return 0; }
    out[n] = 0;
    return 1;
}

int platform_resource_path(const char *name, char *out, size_t cap) {
    if (out && cap) out[0] = 0;
    if (!name || !out || !cap) return 0;
    char exe[1024];
    if (!platform_executable_path(exe, sizeof exe)) return 0;
    char *sep = strrchr(exe, '/');
    if (!sep) return 0;
    *sep = 0;
    snprintf(out, cap, "%s/resources/%s", exe, name);
    if (access(out, R_OK) == 0) return 1;
    snprintf(out, cap, "%s/%s", exe, name);
    if (access(out, R_OK) == 0) return 1;
    out[0] = 0;
    return 0;
}

// ── launching ─────────────────────────────────────────────────────────────────
void platform_open_url(const char *url) {
    if (!url || !url[0]) return;
    char *argv[] = { "xdg-open", (char *)url, NULL };
    pid_t pid;
    posix_spawnp(&pid, "xdg-open", NULL, NULL, argv, environ);
}

void platform_reveal_file(const char *path) {
    if (!path || !path[0]) return;
    char dir[1024];
    snprintf(dir, sizeof dir, "%s", path);
    char *sep = strrchr(dir, '/');
    if (sep && sep != dir) *sep = 0;
    char *argv[] = { "xdg-open", dir, NULL };
    pid_t pid;
    posix_spawnp(&pid, "xdg-open", NULL, NULL, argv, environ);
}

// HTTPS GET, follow redirects, return the FINAL URL. Blocking; worker thread
// only. Verifies the peer against the system CA store (update check is
// notify-only — we still refuse a MITM'd Location).
static int parse_https(const char *url, char *host, size_t hcap,
                       char *path, size_t pcap, int *port) {
    if (strncmp(url, "https://", 8) != 0) return 0;
    const char *h = url + 8;
    const char *slash = strchr(h, '/');
    const char *colon = NULL;
    size_t hlen;
    if (slash) {
        colon = memchr(h, ':', (size_t)(slash - h));
        hlen = (size_t)((colon ? colon : slash) - h);
        snprintf(path, pcap, "%s", slash);
    } else {
        colon = strchr(h, ':');
        hlen = strlen(colon ? colon : h);
        if (colon) hlen = (size_t)(colon - h);
        else hlen = strlen(h);
        snprintf(path, pcap, "/");
    }
    if (!hlen || hlen >= hcap) return 0;
    memcpy(host, h, hlen);
    host[hlen] = 0;
    *port = 443;
    if (colon && (!slash || colon < slash)) *port = atoi(colon + 1);
    if (*port <= 0 || *port > 65535) return 0;
    return 1;
}

int platform_http_final_url(const char *url, char *out, size_t cap) {
    if (!url || !out || !cap) return 0;
    out[0] = 0;
    char cur[512];
    snprintf(cur, sizeof cur, "%s", url);
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return 0;
    SSL_CTX_set_default_verify_paths(ctx);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    int ok = 0;
    for (int hop = 0; hop < 8; hop++) {
        char host[256], path[512], hp[300];
        int port = 443;
        if (!parse_https(cur, host, sizeof host, path, sizeof path, &port)) break;
        snprintf(hp, sizeof hp, "%s:%d", host, port);
        BIO *bio = BIO_new_ssl_connect(ctx);
        SSL *ssl = NULL;
        BIO_get_ssl(bio, &ssl);
        if (!ssl) { BIO_free_all(bio); break; }
        SSL_set_tlsext_host_name(ssl, host);
        SSL_set1_host(ssl, host);
        BIO_set_conn_hostname(bio, hp);
        if (BIO_do_connect(bio) <= 0) { BIO_free_all(bio); break; }
        char req[1200];
        int rn = snprintf(req, sizeof req,
            "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: pepenet-update-check/1\r\n"
            "Connection: close\r\n\r\n", path, host);
        if (BIO_write(bio, req, rn) != rn) { BIO_free_all(bio); break; }
        char buf[4096];
        int n = 0;
        while (n < (int)sizeof buf - 1) {
            int r = BIO_read(bio, buf + n, (int)sizeof buf - 1 - n);
            if (r <= 0) break;
            n += r;
            buf[n] = 0;
            if (strstr(buf, "\r\n\r\n")) break;
        }
        BIO_free_all(bio);
        buf[n] = 0;
        int status = 0;
        if (sscanf(buf, "HTTP/%*s %d", &status) != 1) break;
        char *loc = strcasestr(buf, "\nLocation:");
        if (status >= 300 && status < 400 && loc) {
            loc += 10;
            while (*loc == ' ' || *loc == '\t') loc++;
            char dest[512];
            size_t i = 0;
            while (loc[i] && loc[i] != '\r' && loc[i] != '\n' && i + 1 < sizeof dest)
                dest[i] = loc[i], i++;
            dest[i] = 0;
            if (dest[0] == '/') {
                snprintf(cur, sizeof cur, "https://%s%s", host, dest);
            } else {
                snprintf(cur, sizeof cur, "%s", dest);
            }
            continue;
        }
        if (status >= 200 && status < 300) {
            snprintf(out, cap, "%s", cur);
            ok = 1;
        }
        break;
    }
    SSL_CTX_free(ctx);
    return ok;
}

// ── secret storage (libsecret / Secret Service) ───────────────────────────────
// Values are hex-encoded so a 16-byte wallet seed survives the string API
// (raw bytes can contain NUL). Lookup errors (daemon down, locked, denied)
// return -1 — never "not found", so the wallet will not mint over a live key.
static const SecretSchema k_schema = {
    "org.pepenet.Secret", SECRET_SCHEMA_NONE,
    {
        { "service", SECRET_SCHEMA_ATTRIBUTE_STRING },
        { "account", SECRET_SCHEMA_ATTRIBUTE_STRING },
        { NULL, 0 },
    }
};

static const char *secret_service_name(void) {
    const char *s = getenv("PEPENET_KEYCHAIN_SERVICE");
    return (s && s[0]) ? s : APP_DATA_DIR;
}

static void to_hex(const uint8_t *b, size_t n, char *out, size_t cap) {
    static const char H[] = "0123456789abcdef";
    if (cap < n * 2 + 1) { out[0] = 0; return; }
    for (size_t i = 0; i < n; i++) {
        out[i * 2]     = H[b[i] >> 4];
        out[i * 2 + 1] = H[b[i] & 15];
    }
    out[n * 2] = 0;
}

static int from_hex(const char *s, uint8_t *out, size_t cap) {
    size_t n = strlen(s);
    if (n % 2 || n / 2 > cap) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        unsigned v = 0;
        if (sscanf(s + i * 2, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return (int)(n / 2);
}

int platform_secret_get(const char *account, uint8_t *out, size_t cap) {
    if (!account || !out || !cap) return 0;
    GError *err = NULL;
    gchar *pw = secret_password_lookup_sync(&k_schema, NULL, &err,
                    "service", secret_service_name(),
                    "account", account, NULL);
    if (err) { g_error_free(err); return -1; }
    if (!pw) return 0;
    int n = from_hex(pw, out, cap);
    secret_password_free(pw);
    return n < 0 ? 0 : n;
}

int platform_secret_set(const char *account, const uint8_t *secret, size_t len) {
    if (!account || !secret || !len || len > 256) return 0;
    char hex[520], label[200];
    to_hex(secret, len, hex, sizeof hex);
    snprintf(label, sizeof label, "%s/%s", secret_service_name(), account);
    GError *err = NULL;
    gboolean ok = secret_password_store_sync(&k_schema, SECRET_COLLECTION_DEFAULT,
                    label, hex, NULL, &err,
                    "service", secret_service_name(),
                    "account", account, NULL);
    if (err) g_error_free(err);
    return ok ? 1 : 0;
}

int platform_secret_del(const char *account) {
    if (!account) return 0;
    GError *err = NULL;
    gboolean ok = secret_password_clear_sync(&k_schema, NULL, &err,
                    "service", secret_service_name(),
                    "account", account, NULL);
    if (err) {
        // "not found" is success; anything else is a real failure
        int absent = strstr(err->message ? err->message : "", "No such") != NULL;
        g_error_free(err);
        return absent || ok ? 1 : 0;
    }
    return 1;
}

// ── launch-at-login (XDG autostart) ───────────────────────────────────────────
static void autostart_path(char *out, size_t cap) {
    const char *xdg = getenv("XDG_CONFIG_HOME");
    if (xdg && xdg[0] == '/')
        snprintf(out, cap, "%s/autostart/" APP_BUNDLE_ID ".desktop", xdg);
    else
        snprintf(out, cap, "%s/.config/autostart/" APP_BUNDLE_ID ".desktop", home_dir());
}

int platform_loginitem_state(void) {
    char p[600];
    autostart_path(p, sizeof p);
    return access(p, F_OK) == 0 ? 1 : 0;
}

int platform_loginitem_set(int on) {
    char p[600];
    autostart_path(p, sizeof p);
    if (!on) { unlink(p); return 1; }
    char exe[1024];
    if (!platform_executable_path(exe, sizeof exe)) return 0;
    char dir[600];
    snprintf(dir, sizeof dir, "%s", p);
    char *sep = strrchr(dir, '/');
    if (sep) { *sep = 0; mkdir_p(dir); }
    FILE *f = fopen(p, "w");
    if (!f) return 0;
    fprintf(f,
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=%s\n"
        "Exec=\"%s\" --background\n"
        "X-GNOME-Autostart-enabled=true\n"
        "Hidden=false\n",
        APP_NAME, exe);
    fclose(f);
    return 1;
}

#endif /* !__APPLE__ */
#endif /* !_WIN32 */
#endif /* linux/unix */
