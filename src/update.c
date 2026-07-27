// update.c — the notify-only update check (see update.h for the trust rules).
#include "update.h"
#include "appconf.h"
#include "platform.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef PEPENET_VERSION
#define PEPENET_VERSION "0.0.0"    // CMake stamps the real one; dev fallback
#endif

#define CHECK_EVERY (24 * 3600)    // seconds between checks
#define RETRY_AFTER (2 * 3600)     // a failed check retries sooner

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static char g_latest[32];          // set once a strictly-newer tag is seen
static int  g_started;

// "1.2.3" (optional leading 'v') → triple; 0 on anything else. Trailing
// junk rejected — a tag that isn't plainly a version is not an update.
static int parse3(const char *s, int v[3]) {
    if (*s == 'v') s++;
    char tail;
    if (sscanf(s, "%d.%d.%d%c", &v[0], &v[1], &v[2], &tail) != 3) return 0;
    return v[0] >= 0 && v[1] >= 0 && v[2] >= 0;
}

static int newer_than_build(const char *tag) {
    int r[3], b[3];
    if (!parse3(tag, r) || !parse3(PEPENET_VERSION, b)) return 0;
    for (int i = 0; i < 3; i++) {
        if (r[i] != b[i]) return r[i] > b[i];
    }
    return 0;
}

// 1 = the check ran (newer or not), 0 = network failure. GitHub redirects
// <releases>/latest to <releases>/tag/<version>; the tag is the final URL's
// last path segment. No releases yet → no redirect → the segment is "latest",
// which parse3 rejects. Every quiet path stays quiet — a check can only ever
// raise the notice, never a dialog, never an action.
static int check_once(void) {
    char fin[512];
    if (!platform_http_final_url(APP_RELEASES_URL "/latest", fin, sizeof fin))
        return 0;
    const char *tag = strrchr(fin, '/');
    tag = tag ? tag + 1 : fin;
    if (newer_than_build(tag)) {
        if (*tag == 'v') tag++;
        pthread_mutex_lock(&g_mu);
        snprintf(g_latest, sizeof g_latest, "%s", tag);
        pthread_mutex_unlock(&g_mu);
    }
    return 1;
}

static void *worker(void *arg) {
    (void)arg;
    for (;;) {
        int ran = check_once();
        pthread_mutex_lock(&g_mu);
        int found = g_latest[0] != 0;
        pthread_mutex_unlock(&g_mu);
        // once a newer release is known the notice stays until the user
        // updates (this binary can never catch up to it) — stop polling
        if (found) return NULL;
        sleep((unsigned)(ran ? CHECK_EVERY : RETRY_AFTER));
    }
    return NULL;
}

void update_start(void) {
    if (g_started) return;
    g_started = 1;
    pthread_t t;
    if (pthread_create(&t, NULL, worker, NULL) == 0)
        pthread_detach(t);
}

const char *update_build_version(void) { return PEPENET_VERSION; }

int update_available(char *ver, size_t cap) {
    pthread_mutex_lock(&g_mu);
    int have = g_latest[0] != 0;
    if (have && ver && cap) snprintf(ver, cap, "%s", g_latest);
    pthread_mutex_unlock(&g_mu);
    return have;
}
