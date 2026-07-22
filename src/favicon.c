// favicon.c — see favicon.h. One worker, one mutex, a flat cache.
#include "favicon.h"
#include "appconf.h"
#include "fetch.h"           // tls_loopback_get (tls_embed)

#define STB_IMAGE_IMPLEMENTATION
#define STBI_ONLY_PNG
#define STBI_ONLY_JPEG
#define STBI_ONLY_GIF
#define STBI_ONLY_BMP
#define STBI_NO_LINEAR
#define STBI_NO_HDR
#include "../vendor/nuklear/example/stb_image.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define FAV_MAX       128
#define FAV_BODY_CAP  (256 * 1024)   // fetch cap — favicons are small
#define FAV_DIM_CAP   512            // decoded side cap (texture memory)
#define FAV_RETRY_S   900

typedef struct {
    char     name[40];
    int      state;                  // FAV_*
    uint8_t *rgba;
    int      w, h;
    int64_t  retry_at;               // FAV_FAIL: re-queue after this
} Fav;

static struct {
    pthread_t th;
    pthread_mutex_t mx;
    pthread_cond_t  cv;
    int booted, stop;
    Fav cache[FAV_MAX];
    int n;
} g = { .mx = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER };

// ── decode: sniff the container, return RGBA (malloc) ────────────────────────
static uint8_t *decode_rgba(const uint8_t *d, size_t n, int *w, int *h);

// 32bpp BI_RGB DIB inside an .ico entry (the classic case stb can't read: an
// ico entry is a BARE BITMAPINFOHEADER — no BMP file header — and its height
// counts the AND mask too). BGRA bottom-up → RGBA top-down.
static uint8_t *decode_ico_dib(const uint8_t *d, size_t n, int *w, int *h) {
    if (n < 40) return NULL;
    uint32_t hsz = d[0] | d[1] << 8 | d[2] << 16 | (uint32_t)d[3] << 24;
    int32_t  bw  = (int32_t)(d[4] | d[5] << 8 | d[6] << 16 | (uint32_t)d[7] << 24);
    int32_t  bh  = (int32_t)(d[8] | d[9] << 8 | d[10] << 16 | (uint32_t)d[11] << 24);
    uint16_t bpp = (uint16_t)(d[14] | d[15] << 8);
    uint32_t cmp = d[16] | d[17] << 8 | d[18] << 16 | (uint32_t)d[19] << 24;
    if (hsz < 40 || bpp != 32 || cmp != 0) return NULL;   // BI_RGB 32bpp only
    int32_t ih = bh / 2;                                  // XOR half; AND mask below
    if (bw <= 0 || ih <= 0 || bw > FAV_DIM_CAP || ih > FAV_DIM_CAP) return NULL;
    size_t need = hsz + (size_t)bw * (size_t)ih * 4;
    if (n < need) return NULL;
    uint8_t *out = malloc((size_t)bw * (size_t)ih * 4);
    if (!out) return NULL;
    const uint8_t *px = d + hsz;
    for (int32_t y = 0; y < ih; y++) {
        const uint8_t *row = px + (size_t)(ih - 1 - y) * (size_t)bw * 4;
        uint8_t *dst = out + (size_t)y * (size_t)bw * 4;
        for (int32_t x = 0; x < bw; x++) {
            dst[x * 4 + 0] = row[x * 4 + 2];
            dst[x * 4 + 1] = row[x * 4 + 1];
            dst[x * 4 + 2] = row[x * 4 + 0];
            dst[x * 4 + 3] = row[x * 4 + 3];
        }
    }
    *w = bw; *h = ih;
    return out;
}

static uint8_t *decode_ico(const uint8_t *d, size_t n, int *w, int *h) {
    if (n < 6 + 16) return NULL;
    int count = d[4] | d[5] << 8;
    if (count <= 0) return NULL;
    // pick the largest entry (w byte 0 = 256)
    size_t best_off = 0, best_len = 0; int best_side = -1;
    for (int i = 0; i < count && 6 + (size_t)(i + 1) * 16 <= n; i++) {
        const uint8_t *e = d + 6 + (size_t)i * 16;
        int side = e[0] ? e[0] : 256;
        uint32_t len = e[8] | e[9] << 8 | e[10] << 16 | (uint32_t)e[11] << 24;
        uint32_t off = e[12] | e[13] << 8 | e[14] << 16 | (uint32_t)e[15] << 24;
        if ((size_t)off + len > n || len == 0) continue;
        if (side > best_side) { best_side = side; best_off = off; best_len = len; }
    }
    if (best_side < 0) return NULL;
    return decode_rgba(d + best_off, best_len, w, h);     // PNG entry or DIB
}

static uint8_t *decode_rgba(const uint8_t *d, size_t n, int *w, int *h) {
    if (n >= 4 && d[0] == 0 && d[1] == 0 && d[2] == 1 && d[3] == 0)
        return decode_ico(d, n, w, h);
    int c = 0;
    uint8_t *px = stbi_load_from_memory(d, (int)n, w, h, &c, 4);
    if (!px && n >= 40) return decode_ico_dib(d, n, w, h); // bare .ico DIB
    if (px && (*w <= 0 || *h <= 0 || *w > FAV_DIM_CAP || *h > FAV_DIM_CAP)) {
        stbi_image_free(px);
        return NULL;
    }
    return px;                                             // stbi malloc = free()-able
}

// ── worker ───────────────────────────────────────────────────────────────────
static void fetch_one(const char *name) {
    char sni[64];
    snprintf(sni, sizeof sni, "%s" APP_DOT_TLD, name);
    uint8_t *body = NULL;
    size_t bn = tls_loopback_get(APP_PROXY_PORT, sni, "/favicon.ico",
                                 &body, FAV_BODY_CAP);
    if (!bn) bn = tls_loopback_get(APP_PROXY_PORT, sni, "/favicon.png",
                                   &body, FAV_BODY_CAP);
    uint8_t *rgba = NULL;
    int w = 0, h = 0;
    if (bn) rgba = decode_rgba(body, bn, &w, &h);
    free(body);

    pthread_mutex_lock(&g.mx);
    for (int i = 0; i < g.n; i++)
        if (strcmp(g.cache[i].name, name) == 0) {
            if (rgba) {
                g.cache[i].rgba = rgba; g.cache[i].w = w; g.cache[i].h = h;
                g.cache[i].state = FAV_READY;
                rgba = NULL;
            } else {
                g.cache[i].state = FAV_FAIL;
                g.cache[i].retry_at = (int64_t)time(NULL) + FAV_RETRY_S;
            }
            break;
        }
    pthread_mutex_unlock(&g.mx);
    free(rgba);
}

static void *worker(void *arg) {
    (void)arg;
    for (;;) {
        char name[40] = "";
        pthread_mutex_lock(&g.mx);
        while (!g.stop) {
            for (int i = 0; i < g.n && !name[0]; i++)
                if (g.cache[i].state == FAV_PENDING)
                    snprintf(name, sizeof name, "%s", g.cache[i].name);
            if (name[0]) break;
            pthread_cond_wait(&g.cv, &g.mx);
        }
        pthread_mutex_unlock(&g.mx);
        if (g.stop) return NULL;
        fetch_one(name);                       // network work outside the lock
    }
}

// ── UI-thread API ────────────────────────────────────────────────────────────
int favicon_query(const char *name, const uint8_t **rgba, int *w, int *h) {
    if (!name || !name[0] || !g.booted) return FAV_NONE;
    int st = FAV_NONE;
    pthread_mutex_lock(&g.mx);
    Fav *f = NULL;
    for (int i = 0; i < g.n && !f; i++)
        if (strcmp(g.cache[i].name, name) == 0) f = &g.cache[i];
    if (!f && g.n < FAV_MAX) {
        f = &g.cache[g.n++];
        memset(f, 0, sizeof *f);
        snprintf(f->name, sizeof f->name, "%s", name);
        f->state = FAV_PENDING;
        pthread_cond_signal(&g.cv);
    }
    if (f) {
        if (f->state == FAV_FAIL && (int64_t)time(NULL) >= f->retry_at) {
            f->state = FAV_PENDING;            // one quiet retry per window
            pthread_cond_signal(&g.cv);
        }
        st = f->state;
        if (st == FAV_READY) {
            if (rgba) *rgba = f->rgba;
            if (w) *w = f->w;
            if (h) *h = f->h;
        }
    }
    pthread_mutex_unlock(&g.mx);
    return st;
}

void favicon_boot(void) {
    if (g.booted) return;
    g.stop = 0;
    if (pthread_create(&g.th, NULL, worker, NULL) == 0) g.booted = 1;
}

void favicon_stop(void) {
    if (!g.booted) return;
    pthread_mutex_lock(&g.mx);
    g.stop = 1;
    pthread_cond_signal(&g.cv);
    pthread_mutex_unlock(&g.mx);
    pthread_join(g.th, NULL);
    for (int i = 0; i < g.n; i++) free(g.cache[i].rgba);
    g.n = 0;
    g.booted = 0;
}
