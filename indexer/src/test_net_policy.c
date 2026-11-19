// test_net_policy.c — unit tests for src/net_policy.c (no sqlite, no P2P).
#include "net_policy.h"
#include <stdio.h>
#include <string.h>

static int g_fail;

#define CK(c, m) do { if (c) printf("  ok   %s\n", m); \
                      else { printf("  FAIL %s\n", m); g_fail++; } } while (0)

int main(void) {
    net_policy_reset();

    printf("-- compact size --\n");
    {
        uint8_t a[] = { 3 };
        uint64_t c; uint32_t o;
        CK(net_policy_read_count(a, 1, &c, &o) && c == 3 && o == 1, "1-byte count");
        uint8_t b[] = { 0xFD, 0xE8, 0x03 };  /* 1000 */
        CK(net_policy_read_count(b, 3, &c, &o) && c == 1000 && o == 3, "0xFD 1000");
        uint8_t big[] = { 0xFE, 0, 0, 0, 0 };
        CK(!net_policy_read_count(big, 5, &c, &o), "0xFE rejected");
        uint8_t empty[] = { 0 };
        CK(!net_policy_read_count(empty, 0, &c, &o), "empty payload");
    }

    printf("-- score / ban --\n");
    {
        int s = 0;
        CK(!net_policy_score_add(&s, 20) && s == 20, "+20 does not ban");
        CK(!net_policy_score_add(&s, 20) && s == 40, "+40 still under 100");
        CK(!net_policy_score_add(&s, 50) && s == 90, "+90 still under");
        CK(net_policy_score_add(&s, 20) && s == 110, "+110 crosses 100");
    }
    {
        time_t now = 1000000;
        CK(!net_policy_banned("1.2.3.4", now), "unknown ip not banned");
        net_policy_ban("1.2.3.4", now);
        CK(net_policy_banned("1.2.3.4", now), "banned immediately");
        CK(!net_policy_banned("1.2.3.5", now), "other ip clean");
        CK(!net_policy_banned("1.2.3.4", now + IDX_BAN_S), "expired after 24h");
        CK(!net_policy_banned("1.2.3.4", now + IDX_BAN_S + 1), "gc dropped expired");
    }
    {
        time_t now = 2000000;
        net_policy_reset();
        for (int i = 0; i < IDX_BAN_CAP; i++) {
            char ip[32];
            snprintf(ip, sizeof ip, "10.0.%d.%d", i / 256, i % 256);
            net_policy_ban(ip, now + (i == 0 ? 0 : 10)); /* first expires sooner if we bump until */
        }
        /* table full: a new ban must evict oldest until, not refuse */
        net_policy_ban("9.9.9.9", now + 100);
        CK(net_policy_banned("9.9.9.9", now + 100), "full table still accepts a new ban");
    }

    printf("-- getdata window --\n");
    {
        int blocks = 0; uint32_t bytes = 0; time_t win = 0;
        time_t t = 100;
        CK(net_policy_getdata_ok(&blocks, &bytes, &win, t, 1, 1024 * 1024), "first 1 MiB block");
        for (int i = 0; i < 15; i++)
            if (!net_policy_getdata_ok(&blocks, &bytes, &win, t, 1, 1024 * 1024)) {
                g_fail++; printf("  FAIL block %d of 16 refused\n", i + 2); break;
            }
        CK(blocks == 16, "16 blocks fill the window");
        CK(!net_policy_getdata_ok(&blocks, &bytes, &win, t, 1, 1024), "17th block refused");
        CK(net_policy_getdata_ok(&blocks, &bytes, &win, t + IDX_GETDATA_WINDOW_S, 1, 1024),
           "new window after 10 s");
        CK(net_policy_getdata_items_ok(0) && net_policy_getdata_items_ok(127), "items 0..127 ok");
        CK(!net_policy_getdata_items_ok(128), "item 128 refused");
    }
    {
        int blocks = 0; uint32_t bytes = 0; time_t win = 0;
        time_t t = 200;
        CK(net_policy_getdata_ok(&blocks, &bytes, &win, t, 0, IDX_GETDATA_BYTES), "exact byte cap");
        CK(!net_policy_getdata_ok(&blocks, &bytes, &win, t, 0, 1), "one more byte refused");
    }

    if (g_fail) { printf("test_net_policy: %d FAIL\n", g_fail); return 1; }
    printf("test_net_policy: ALL PASSED\n");
    return 0;
}
