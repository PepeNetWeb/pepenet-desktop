// model_demo.c — the --demo fixtures. Names/market/wallet content matches the
// pepenet design mockups card-for-card so the running app can be eyeballed
// against them; also the only way to exercise wallet/names/market flows
// without a synced chain.
#include "model.h"
#include "wallet.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#define KO(x) ((int64_t)((double)(x) * 1e8 + 0.5))
#define DAYS(n) ((int64_t)(n) * 86400)

static int64_t on_date(int mon, int day, int year) {
    struct tm tm = { 0 };
    tm.tm_year = year - 1900; tm.tm_mon = mon - 1; tm.tm_mday = day;
    tm.tm_hour = 12;
    return (int64_t)mktime(&tm);
}

void model_demo_load(void) {
    M.has_wallet = 1;
    M.balance = KO(12.401);
    snprintf(M.address, sizeof M.address, "PuCysJ8kR2mT4vN9wQxL7bZaH3dF6gY1hFL");

    // ── names (3a) ───────────────────────────────────────────────────────────
    M.nnames = 5;
    snprintf(M.names[0].name, sizeof M.names[0].name, "shibs-list");
    M.names[0].st = NS_OWNED;  M.names[0].expiry = on_date(4, 2, 2027);
    M.names[0].bytes_left = ZONE_BUDGET;
    snprintf(M.names[1].name, sizeof M.names[1].name, "doge-p2p");
    M.names[1].st = NS_OWNED;  M.names[1].expiry = on_date(7, 15, 2026);   // 12d — renew soon
    M.names[1].bytes_left = 34000;
    snprintf(M.names[2].name, sizeof M.names[2].name, "wow");
    M.names[2].st = NS_LISTED; M.names[2].expiry = M.now + DAYS(128);
    M.names[2].list_price = KO(40);
    M.names[2].list_window_end = M.now + DAYS(5);
    M.names[2].bytes_left = 12000;
    // windows per protocol: reserve = 5h (SM_RESERVE_WINDOW), direct offer = 2h
    snprintf(M.names[3].name, sizeof M.names[3].name, "rare-pepe");
    M.names[3].st = NS_RESERVED; M.names[3].expiry = M.now + DAYS(203);
    M.names[3].reserve_end = M.now + 4 * 3600 + 7 * 60;
    snprintf(M.names[4].name, sizeof M.names[4].name, "moon");
    M.names[4].st = NS_OFFERED; M.names[4].expiry = M.now + DAYS(300);
    snprintf(M.names[4].offered_to, sizeof M.names[4].offered_to, "Pk9wZa…4mQrT");
    M.names[4].offer_price = KO(120);
    M.names[4].reserve_end = M.now + 3600 + 48 * 60;

    // ── market (3d) ──────────────────────────────────────────────────────────
    // others' open listings + reserved-by-another + our own "wow" listing
    // (name[2] above), so the browse feed and the "your listing" row both show
    M.nlist = 5;
    snprintf(M.listings[0].name, sizeof M.listings[0].name, "satoshi");
    M.listings[0].price = KO(1200); M.listings[0].window_end = M.now + DAYS(2) + 4 * 3600;
    snprintf(M.listings[1].name, sizeof M.listings[1].name, "gm");
    M.listings[1].price = KO(420);  M.listings[1].window_end = M.now + 6 * 3600;
    snprintf(M.listings[2].name, sizeof M.listings[2].name, "based");
    M.listings[2].price = KO(300);  M.listings[2].window_end = M.now + DAYS(1);
    M.listings[2].reserved_by_other = 1;
    M.listings[2].reserve_end = M.now + 40 * 60;
    snprintf(M.listings[3].name, sizeof M.listings[3].name, "wagmi");
    M.listings[3].price = KO(75);   M.listings[3].window_end = M.now + DAYS(5);
    snprintf(M.listings[4].name, sizeof M.listings[4].name, "wow");   // ours (name[2])
    M.listings[4].price = KO(40);   M.listings[4].window_end = M.now + DAYS(5);
    M.listings[4].is_mine = 1;

    M.noffers = 1;
    snprintf(M.offers[0].name, sizeof M.offers[0].name, "lucky-number");
    M.offers[0].price = KO(88);
    M.offers[0].expires = M.now + 3600 + 27 * 60;   // 2h direct window

    // ── chain status (2c footer) ─────────────────────────────────────────────
    M.height = 4213882;
    M.year_cost = KO(0.0311);
    M.rate = (uint64_t)(M.year_cost / 13);
    M.running = 1; M.synced = 1;
}
