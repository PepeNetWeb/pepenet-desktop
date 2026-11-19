// appinst.h — the runtime instance table. appconf.h stays the default
// (PepeNet) instance so pepenet-desktop and pepenet-web keep their macros.
// A second row (DogeNet) is selected by coin id. Ports on that row are the
// moved set: the dogenet tree reuses pep's ports, which this process must
// not bind while the PepeNet app is running.
#ifndef DNET_APPINST_H
#define DNET_APPINST_H

typedef struct AppInstance {
    const char *coin;           // indexer coin id ("pep", "doge")
    const char *tld;            // DNS suffix, no dot
    const char *data_dir;       // dot-folder name: pepenet / dogenet
    const char *seeds;          // comma-separated overlay seeds
    const char *chain_agent;   // P2P subver
    const char *pf_anchor;      // pf/nft table name
    const char *name;           // brand
    const char *bundle_id;
    const char *releases_url;
    int dns_port;
    int proxy_port;             // DANE listener
    int pac_port;               // PAC + CONNECT front door
    int pf_port;                // pf/nft rdr target
} AppInstance;

const AppInstance *app_instance_default(void);
const AppInstance *app_instance_by_coin(const char *coin);

/* Multi-instance data root (<base>/<coin>/). Empty means the desktop
 * default (~/.<APP_DATA_DIR> via platform_data_dir). greatdane-node sets
 * this; pepenet-desktop does not. */
void app_set_data_base(const char *dir);
const char *app_data_base(void);

#endif
