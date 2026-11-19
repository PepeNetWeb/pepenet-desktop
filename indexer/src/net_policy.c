// net_policy.c — in-memory score/ban + getdata window. Serve-thread only.
#include "net_policy.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    char   ip[46];
    time_t until;
} Ban;

static Ban g_ban[IDX_BAN_CAP];
static int g_nban;

static void ban_gc(time_t now) {
    int w = 0;
    for (int i = 0; i < g_nban; i++) {
        if (g_ban[i].until > now) {
            if (w != i) g_ban[w] = g_ban[i];
            w++;
        }
    }
    g_nban = w;
}

int net_policy_read_count(const uint8_t *pl, uint32_t n, uint64_t *cnt, uint32_t *off) {
    if (!pl || n < 1 || !cnt || !off) return 0;
    uint32_t o = 0;
    uint64_t c = pl[o++];
    if (c == 0xFD) {
        if (n < 3) return 0;
        c = (uint64_t)pl[o] | ((uint64_t)pl[o + 1] << 8);
        o += 2;
    } else if (c >= 0xFE) {
        return 0;
    }
    *cnt = c;
    *off = o;
    return 1;
}

int net_policy_banned(const char *ip, time_t now) {
    if (!ip || !*ip) return 0;
    ban_gc(now);
    for (int i = 0; i < g_nban; i++)
        if (!strcmp(g_ban[i].ip, ip)) return 1;
    return 0;
}

void net_policy_ban(const char *ip, time_t now) {
    if (!ip || !*ip) return;
    ban_gc(now);
    for (int i = 0; i < g_nban; i++) {
        if (!strcmp(g_ban[i].ip, ip)) {
            g_ban[i].until = now + IDX_BAN_S;
            return;
        }
    }
    if (g_nban >= IDX_BAN_CAP) {
        int oldest = 0;
        for (int i = 1; i < g_nban; i++)
            if (g_ban[i].until < g_ban[oldest].until) oldest = i;
        g_ban[oldest] = g_ban[g_nban - 1];
        g_nban--;
    }
    snprintf(g_ban[g_nban].ip, sizeof g_ban[g_nban].ip, "%s", ip);
    g_ban[g_nban].until = now + IDX_BAN_S;
    g_nban++;
}

int net_policy_score_add(int *score, int n) {
    if (!score || n <= 0) return 0;
    int before = *score;
    *score += n;
    if (*score > IDX_BAN_SCORE * 4) *score = IDX_BAN_SCORE * 4;
    return before < IDX_BAN_SCORE && *score >= IDX_BAN_SCORE;
}

int net_policy_getdata_ok(int *blocks, uint32_t *bytes, time_t *win, time_t now,
                          int add_blocks, uint32_t add_bytes) {
    if (!blocks || !bytes || !win) return 0;
    if (!*win || now - *win >= IDX_GETDATA_WINDOW_S) {
        *win = now;
        *blocks = 0;
        *bytes = 0;
    }
    if (add_blocks && *blocks + add_blocks > IDX_GETDATA_BLOCKS) return 0;
    if (add_bytes && (uint64_t)*bytes + (uint64_t)add_bytes > IDX_GETDATA_BYTES) return 0;
    *blocks += add_blocks;
    *bytes  += add_bytes;
    return 1;
}

int net_policy_getdata_items_ok(int examined) {
    return examined >= 0 && examined < IDX_GETDATA_ITEMS;
}

void net_policy_reset(void) {
    g_nban = 0;
    memset(g_ban, 0, sizeof g_ban);
}
