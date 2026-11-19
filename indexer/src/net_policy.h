// net_policy.h — Bitcoin-style local DoS policy (caps, score, ban, getdata budget).
// Not a wire change. See pepenet-desktop/docs/DOS.md.
#ifndef IDX_NET_POLICY_H
#define IDX_NET_POLICY_H

#include <stdint.h>
#include <time.h>

#define IDX_MSG_MAX           (2u * 1024 * 1024)
#define IDX_MAX_INV_SZ        50000
#define IDX_MAX_ADDR          1000
#define IDX_BAN_SCORE         100
#define IDX_BAN_S             (24 * 3600)
#define IDX_BAN_CAP           4096
#define IDX_GETDATA_WINDOW_S  10
#define IDX_GETDATA_BLOCKS    16
#define IDX_GETDATA_BYTES     (16u * 1024 * 1024)
#define IDX_GETDATA_ITEMS     128

/* CompactSize count at payload start (inv/getdata/addr). 0xFE/0xFF rejected. */
int  net_policy_read_count(const uint8_t *pl, uint32_t n, uint64_t *cnt, uint32_t *off);

int  net_policy_banned(const char *ip, time_t now);      /* 1 = refuse */
void net_policy_ban(const char *ip, time_t now);         /* evict expired, then oldest until */
int  net_policy_score_add(int *score, int n);            /* 1 = this add crossed 100 */

/* 1 if the served body fits the 10 s window (counters incremented). 0 = skip. */
int  net_policy_getdata_ok(int *blocks, uint32_t *bytes, time_t *win, time_t now,
                           int add_blocks, uint32_t add_bytes);
int  net_policy_getdata_items_ok(int examined);          /* 1 if examined < IDX_GETDATA_ITEMS */

void net_policy_reset(void);                             /* tests */

#endif
