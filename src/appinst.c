// appinst.c — pep row is filled from appconf.h so it cannot drift from the
// default build. doge row is the dogenet-desktop instance with ports moved
// off the PepeNet set.
#include "indexer.h"            // IDX_DNET_MARK, used by APP_CHAIN_AGENT
#include "appconf.h"
#include "appinst.h"

#include <stdio.h>
#include <string.h>

#ifndef PEPENET_VERSION
#define PEPENET_VERSION "0.0.0"
#endif

static const AppInstance APP_INSTANCES[] = {
    {
        .coin         = APP_COIN,
        .tld          = APP_TLD,
        .data_dir     = APP_DATA_DIR,
        .seeds        = APP_SEED_PEER,
        .chain_agent  = APP_CHAIN_AGENT,
        .pf_anchor    = APP_PF_ANCHOR,
        .name         = APP_NAME,
        .bundle_id    = APP_BUNDLE_ID,
        .releases_url = APP_RELEASES_URL,
        .dns_port     = APP_DNS_PORT,
        .proxy_port   = APP_PROXY_PORT,
        .pac_port     = APP_PAC_PORT,
        .pf_port      = APP_PROXY_PF_PORT,
    },
    {
        .coin         = "doge",
        .tld          = "doge",
        .data_dir     = "dogenet",
        .seeds        = "dogenet.shibpost.com,seed.dogecoin.services",
        .chain_agent  = "/dogenet-desktop:" PEPENET_VERSION "/",
        .pf_anchor    = "dogenet-doge",
        .name         = "DogeNet",
        .bundle_id    = "com.dogenet.app",
        .releases_url = "https://github.com/DogeNetWeb/dogenet-desktop/releases",
        .dns_port     = 25353,
        .proxy_port   = 18443,
        .pac_port     = 18444,
        .pf_port      = 18445,
    },
};

static char g_base[512];

const AppInstance *app_instance_default(void) { return &APP_INSTANCES[0]; }

const AppInstance *app_instance_by_coin(const char *coin) {
    if (!coin || !coin[0]) return app_instance_default();
    for (size_t i = 0; i < sizeof APP_INSTANCES / sizeof APP_INSTANCES[0]; i++)
        if (!strcmp(APP_INSTANCES[i].coin, coin)) return &APP_INSTANCES[i];
    return NULL;
}

void app_set_data_base(const char *dir) {
    if (!dir) { g_base[0] = 0; return; }
    snprintf(g_base, sizeof g_base, "%s", dir);
}

const char *app_data_base(void) { return g_base; }
