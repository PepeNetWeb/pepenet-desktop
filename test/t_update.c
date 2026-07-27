/* t_update.c — the notify-only update check (update.c). This module's whole
 * contract is "a banner may appear, nothing else may happen", so what needs
 * proving is the QUIET side: every malformed, missing, equal, or older tag —
 * and every network failure — must leave the notice unraised. The loud side
 * is one path: a well-formed, strictly-newer tag raises it with the version
 * string GitHub's /releases/latest redirect landed on (v-prefix stripped).
 *
 * Hermetic: platform_http_final_url is stubbed with canned final URLs; the
 * suite includes update.c directly to reach its statics, and pins its own
 * PEPENET_VERSION so the assertions are independent of the CMake version.
 * update_start (the thread + 24 h sleep loop) is deliberately not run here —
 * it adds nothing testable beyond check_once, which is.
 */
#include <stdio.h>
#include <string.h>
#include <stddef.h>

static const char *g_fake;              /* canned "final URL"; NULL = net down */
int platform_http_final_url(const char *url, char *out, size_t cap) {
    (void)url;
    if (!g_fake) return 0;
    snprintf(out, cap, "%s", g_fake);
    return 1;
}

#define PEPENET_VERSION "0.2.0"         /* the pinned test-build version */
#include "update.c"

static int g_fail, g_ok, g_nfail;
#define CHECK(cond, name) do { \
    if (cond) { printf("ok   %s\n", name); g_ok++; } \
    else      { printf("FAIL %s\n", name); g_fail = 1; g_nfail++; } \
} while (0)

static void reset(void) { g_latest[0] = 0; }
static int quiet_after(const char *final_url) {
    char v[32];
    g_fake = final_url;
    reset();
    check_once();
    return !update_available(v, sizeof v);
}

int main(void) {
    char v[32];
    int t[3];

    /* tag grammar: exactly three non-negative numeric components, optional
     * leading 'v', nothing else — anything looser is not an update */
    CHECK(parse3("0.2.1", t) && t[0] == 0 && t[1] == 2 && t[2] == 1, "parse3 plain triple");
    CHECK(parse3("v1.0.0", t) && t[0] == 1, "parse3 accepts leading v");
    CHECK(!parse3("latest", t), "parse3 rejects 'latest' (the no-releases sentinel)");
    CHECK(!parse3("0.2", t), "parse3 rejects two components");
    CHECK(!parse3("0.2.1-rc1", t), "parse3 rejects trailing junk");
    CHECK(!parse3("", t), "parse3 rejects empty");

    /* strictly-newer, numeric per component (never lexicographic) */
    CHECK(newer_than_build("0.2.1"), "patch above build is newer");
    CHECK(newer_than_build("1.0.0"), "major above build is newer");
    CHECK(!newer_than_build("0.2.0"), "the build itself is not newer");
    CHECK(!newer_than_build("0.1.9"), "older is not newer");
    CHECK(newer_than_build("0.10.0"), "numeric compare: 0.10.0 > 0.2.0");

    CHECK(!strcmp(update_build_version(), "0.2.0"), "build version accessor");

    /* the loud path: a strictly-newer tag raises the notice, v-prefix stripped */
    g_fake = "https://github.com/PepeNetWeb/pepenet-desktop/releases/tag/0.2.1";
    reset(); check_once();
    CHECK(update_available(v, sizeof v) && !strcmp(v, "0.2.1"),
          "newer tag redirect raises the notice with its version");
    g_fake = "https://github.com/PepeNetWeb/pepenet-desktop/releases/tag/v0.3.0";
    reset(); check_once();
    CHECK(update_available(v, sizeof v) && !strcmp(v, "0.3.0"),
          "v-prefixed tag raises with the prefix stripped");

    /* every quiet path stays quiet */
    CHECK(quiet_after("https://github.com/PepeNetWeb/pepenet-desktop/releases/latest"),
          "no releases (404, no redirect) stays quiet");
    CHECK(quiet_after("https://github.com/PepeNetWeb/pepenet-desktop/releases/tag/0.2.0"),
          "current release stays quiet");
    CHECK(quiet_after("https://github.com/PepeNetWeb/pepenet-desktop/releases/tag/0.1.2"),
          "older release stays quiet");
    CHECK(quiet_after("https://github.com/PepeNetWeb/pepenet-desktop/releases/tag/0.3.0-rc1"),
          "non-release tag shape stays quiet");
    CHECK(quiet_after("no-slashes-at-all"), "degenerate final URL stays quiet");
    g_fake = NULL;
    reset();
    CHECK(!check_once(), "network failure reports as failed check (fast retry)");
    CHECK(!update_available(v, sizeof v), "network failure stays quiet");

    printf("%d ok, %d failed\n", g_ok, g_nfail);
    return g_fail;
}
