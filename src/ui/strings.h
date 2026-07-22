// strings.h — every user-facing string in the app, in ONE table.
//
// Why: copy tweaks are edits to THIS file only, and localization later is a
// second table keyed by the same ids (ui_str picks the table; strings.c).
//
// Rules for keeping it that way:
//   - code never draws a quoted literal; it draws TR(S_...) — and because the
//     same id feeds both dk_w measurement and the draw call, widths can't
//     drift from the text;
//   - entries ending in _FMT are printf format strings — keep the specifiers
//     (count, order, types) intact when editing the copy around them;
//   - pure glyphs (‹ › ▴ ▾ · the 🔒 padlock, "@" as the DNS apex) stay inline
//     in code: they are layout/notation, not copy. A string that MIXES words
//     and a glyph lives here whole;
//   - instance/brand strings (APP_NAME, the TLD, ports) stay in appconf.h —
//     entries here may splice them in by literal concatenation;
//   - ids are S_<AREA>_<MEANING> (area = screen or dialog); strings shared
//     verbatim across screens live in the common section.
#ifndef DNET_STRINGS_H
#define DNET_STRINGS_H

#include "../appconf.h"

// X(id, english)
#define DNET_STRINGS(X) \
    /* ── common verbs & bits (shared verbatim across screens) ── */ \
    X(S_CANCEL,             "cancel") \
    X(S_CLOSE,              "close") \
    X(S_QUIT,               "quit") \
    X(S_RETRY,              "retry") \
    X(S_EDIT,               "edit") \
    X(S_DELETE,             "delete") \
    /* ── sync states (balance dropdown + footer pill) ── */ \
    X(S_SYNC_SYNCED,        "synced") \
    X(S_SYNC_SYNCING,       "syncing\xE2\x80\xA6") \
    X(S_SYNC_UNREACHABLE,   "peer unreachable \xE2\x80\x94 retrying") \
    X(S_SYNC_CONNECTING,    "connecting\xE2\x80\xA6") \
    /* ── per-name DNS screen (view_dns.c) ── */ \
    X(S_DNS_WHICH,          "DNS") \
    X(S_DNS_LINK_SSL,       "SSL \xE2\x80\xBA") \
    X(S_DNS_EMPTY_NONAME,   "register a name to publish a zone") \
    X(S_DNS_RECORDS,        "DNS records") \
    X(S_DNS_NRECORDS_FMT,   "%d record%s") \
    X(S_DNS_ADD_RECORD,     "+ add record") \
    X(S_COL_TYPE,           "TYPE") \
    X(S_COL_HOST,           "HOST") \
    X(S_COL_VALUE,          "VALUE") \
    X(S_COL_TTL,            "TTL") \
    X(S_DNS_EMPTY_DEMO,     "live zone records show here (demo has none)") \
    X(S_DNS_EMPTY,          "no records yet \xE2\x80\x94 add one") \
    X(S_DNS_SYS_FOOT,       "\xF0\x9F\x94\x92 managed on the SSL page") \
    X(S_DNS_LASTPUB_FMT,    "last: %s") \
    X(S_DNS_FOOTNOTE,       "records publish to the DNS mesh, owner-signed by this wallet \xC2\xB7 " \
                            "TXT host \"_site\" is your Discover description") \
    X(S_DNS_USAGE_FMT,      "zone storage  %lld / %d bytes") \
    X(S_DNS_USAGE_NOTE,     "edits replace \xC2\xB7 deletes keep a small tombstone \xC2\xB7 clear reclaims everything") \
    X(S_DNS_CLEAR_BTN,      "clear zone\xE2\x80\xA6") \
    X(S_DLG_DNSCLEAR_TITLE, "clear zone") \
    X(S_DLG_DNSCLEAR_BODY,  "publishes a signed clear: every record and delete-tombstone in this " \
                            "zone is voided on every mirror and their bytes are reclaimed. the name " \
                            "keeps resolving only what you re-add afterwards. free \xE2\x80\x94 no transaction.") \
    X(S_DLG_DNSCLEAR_CANCEL,"keep records") \
    X(S_DLG_DNSCLEAR_OK,    "Clear zone") \
    /* ── tab strip (ui.c) ── */ \
    X(S_TAB_DISCOVER,       "Discover") \
    X(S_TAB_NAMES,          "My Names") \
    X(S_TAB_MARKET,         "Name Market") \
    /* ── Discover screen (view_discover.c) ── */ \
    X(S_DISC_INFO,          "INFO") \
    X(S_DISC_LAPSED,        "LAPSED") \
    X(S_DISC_NOSITE,        "registered, no site yet — no A / TLSA published") \
    X(S_DISC_NODESC,        "no description published") \
    X(S_DISC_SEARCH_PH,     "search names & descriptions\xE2\x80\xA6") \
    X(S_DISC_EMPTY_DEMO,    "the " APP_DOT_TLD " directory is live data (demo has none)") \
    X(S_DISC_SCANNING,      "scanning the namespace…") \
    X(S_DISC_SCAN_CHAIN,    "scanning the chain — the directory populates as sync folds") \
    X(S_DISC_NOMATCH,       "no match") \
    X(S_DISC_NOZONES,       "no " APP_DOT_TLD " zones seen yet") \
    X(S_DISC_FOOT_FMT,      "%d site%s \xC2\xB7 directory rebuilt in %d ms") \
    /* ── balance dropdown + selection-bar overflow (popups.c) ── */ \
    X(S_POP_BALANCE,        "BALANCE") \
    X(S_POP_NOWALLET,       "no wallet yet") \
    X(S_POP_RECEIVE,        "Receive") \
    X(S_POP_SEND,           "Send") \
    X(S_POP_SYNC,           "sync") \
    X(S_POP_RENT_RATE,      "rent rate") \
    X(S_POP_RENT_FMT,       "%s \xE2\xB1\xA3 / yr") \
    X(S_POP_MESH_PEERS,     "mesh peers") \
    X(S_POP_NCONN_FMT,      "%d connected") \
    X(S_POP_STARTING,       "starting\xE2\x80\xA6") \
    X(S_POP_RESOLVER,       "resolver") \
    X(S_POP_PORT_UP_FMT,    ":%d up") \
    X(S_POP_NOT_RESPONDING, "not responding") \
    X(S_POP_PROXY,          "proxy") \
    X(S_POP_DOWN,           "down") \
    X(S_POP_SETTINGS,       "Settings") \
    X(S_POP_TRANSFER_N_FMT, "Transfer %d") \
    X(S_POP_RELEASE_N_FMT,  "Release %d") \
    /* ── status footer (ui.c; demo/unreachable also shown in the balance dropdown) ── */ \
    X(S_FOOT_DEMO_DATA,     "demo data") \
    X(S_FOOT_UNREACHABLE,   "peer unreachable") \
    X(S_FOOT_BUSY_FMT,      "\xE2\x8F\xB3 %s — signing + broadcasting…") \
    X(S_FOOT_DRYRUN_FMT,    "\xE2\x9C\x93 %s — dry run: built, signed, self-checked (not broadcast)") \
    X(S_FOOT_SENT_NOECHO_FMT, "\xE2\x9C\x93 %s sent · txid %.8s… · peer hasn't echoed it yet") \
    X(S_FOOT_SENT_FMT,      "\xE2\x9C\x93 %s sent · txid %.8s… · confirms next block") \
    X(S_FOOT_INFLIGHT_HOLD_FMT, "\xE2\x8F\xB3 %d in flight \xC2\xB7 %d queued — %s") \
    X(S_FOOT_INFLIGHT_QUEUED_FMT, "\xE2\x8F\xB3 %d in flight \xC2\xB7 %d queued — the chain confirms next block") \
    X(S_FOOT_INFLIGHT_FMT,  "\xE2\x8F\xB3 %d tx%s in flight — confirms next block (~1 min)") \
    X(S_FOOT_CLAIM_WAIT,    "\xE2\x8F\xB3 commit confirming — the claim fires on the next block") \
    X(S_FOOT_SETTLE_WAIT,   "\xE2\x8F\xB3 reserve confirming — the settle fires when it folds") \
    X(S_FOOT_WEB_DEGRADED_FMT, "web access degraded — %s") \
    X(S_FOOT_RESOLVER_DOWN, "resolver down") \
    X(S_FOOT_PROXY_DOWN,    "proxy down") \
    X(S_FOOT_IDLE,          "idle") \
    X(S_FOOT_INCOMING_FMT,  "\xE2\x86\x93 %s incoming") \
    /* ── shared across view_screens.c screens ── */ \
    X(S_SCR_NO_WALLET,          "no wallet yet") \
    X(S_SCR_NO_WALLET_SUB,      "the seed ceremony arrives with the wallet milestone") \
    X(S_SCR_KEY_DENIED,         "wallet key locked") \
    X(S_SCR_KEY_DENIED_SUB,     "macOS denied keychain access \xE2\x80\x94 allow the 'pepenet' " \
                                "item in Keychain Access, then relaunch") \
    X(S_SCR_QUEUED_FMT,         "%s queued \xC2\xB7 confirms next block") \
    X(S_SCR_RENEW,              "renew") \
    X(S_SCR_SELL,               "sell") \
    X(S_SCR_OFFER,              "offer") \
    X(S_SCR_TRANSFER,           "transfer") \
    X(S_SCR_RELEASE,            "release") \
    X(S_SCR_CLAIM,              "claim") \
    X(S_SCR_BADGE_RESERVED,     "RESERVED") \
    /* ── My Names screen ── */ \
    X(S_NAMES_COUNT_FMT,        "%d name%s \xC2\xB7 %d live") \
    X(S_NAMES_REGISTER,         "+ register a name") \
    X(S_NAMES_FILTER_PH,        "filter\xE2\x80\xA6") \
    X(S_NAMES_MARKET_OP,        "market op") \
    X(S_NAMES_CLAIMING_SUB,     "commit \xE2\x86\x92 claim in flight \xC2\xB7 owned once it folds") \
    X(S_NAMES_EXPIRES_SOON_FMT, "expires %s — renew soon") \
    X(S_NAMES_EXPIRES_FMT,      "expires %s") \
    X(S_NAMES_LISTED_FMT,       "listed %s · window %s left") \
    X(S_NAMES_RESERVED_SUB,     "buyer reserved · can't renew now") \
    X(S_NAMES_OFFERED_FMT,      "offered to %s · %s") \
    X(S_NAMES_BADGE_LIVE,       "LIVE") \
    X(S_NAMES_BADGE_OWNED,      "OWNED") \
    X(S_NAMES_BADGE_LISTED,     "LISTED") \
    X(S_NAMES_BADGE_CLAIMING,   "CLAIMING") \
    X(S_NAMES_BADGE_OFFERED,    "OFFERED") \
    X(S_NAMES_BADGE_QUEUED,     "QUEUED") \
    X(S_NAMES_SSL,              "ssl") \
    X(S_NAMES_DNS,              "dns") \
    X(S_NAMES_EMPTY_DEMO,       "no names yet") \
    X(S_NAMES_EMPTY,            "no names yet — register one above") \
    X(S_NAMES_NSEL_FMT,         "%d selected") \
    X(S_NAMES_CLEAR,            "clear") \
    X(S_NAMES_RENEW_N_FMT,      "Renew %d") \
    X(S_NAMES_NOTHING_ACT,      "nothing actionable") \
    /* ── Name Market screen ── */ \
    X(S_MKT_OFFERS_HDR,         "OFFERS TO ME") \
    X(S_MKT_PAY_QUEUED,         "pay queued · confirms next block") \
    X(S_MKT_SOLD_FMT,           "sold to you at %s · pay to settle") \
    X(S_MKT_PAY_FMT,            "Pay %s \xE2\xB1\xA3") \
    X(S_MKT_LEFT_FMT,           "%s left") \
    X(S_MKT_LISTINGS_HDR,       "LISTINGS") \
    X(S_MKT_SORT_PRICE,         "price \xE2\x96\xBE") \
    X(S_MKT_SEARCH_PH,          "search names…") \
    X(S_MKT_WHAT_SETTLE,        "settle") \
    X(S_MKT_WHAT_RESERVE,       "reserve") \
    X(S_MKT_RECLAIM,            "reclaim") \
    X(S_MKT_RECLAIMING_SUB,     "reclaiming · settle to finish") \
    X(S_MKT_YOURS_RESERVED_SUB, "your listing · a buyer reserved it") \
    X(S_MKT_YOURS_CLOSED_SUB,   "your listing · window closed") \
    X(S_MKT_YOURS_SUBDUST_FMT,  "your listing · sub-dust price — unlists in %s") \
    X(S_MKT_YOURS_LEFT_FMT,     "your listing · %s left") \
    X(S_MKT_RESERVED_OTHER_FMT, "reserved by another · %s left") \
    X(S_MKT_RESERVED_YOU_FMT,   "reserved by you · settle within %s") \
    X(S_MKT_WINDOW_CLOSED,      "window closed") \
    X(S_MKT_SUBDUST_SUB,        "un-executable · pay-leg below the dust floor") \
    X(S_MKT_DH_LEFT_FMT,        "%lldd %lldh left") \
    X(S_MKT_SETTLE,             "Settle") \
    X(S_MKT_BADGE_YOURS,        "YOURS") \
    X(S_MKT_BID,                "bid") \
    X(S_MKT_EMPTY_SEARCH,       "no names match your search") \
    X(S_MKT_EMPTY_SYNCING,      "still syncing — listings appear as blocks arrive") \
    X(S_MKT_EMPTY,              "no open listings right now") \
    /* ── Receive screen ── */ \
    X(S_RECV_TITLE,             "Receive") \
    X(S_RECV_SCAN_DEMO,         "scan or copy to get paid \xE2\xB1\xA3") \
    X(S_RECV_SCAN,              "scan or copy to get paid \xE2\xB1\xA3 — fund it to claim names") \
    X(S_RECV_ADDR_HDR,          "YOUR WALLET ADDRESS") \
    X(S_RECV_COPY,              "copy address") \
    X(S_RECV_FOOT,              "one wallet holds every name you own — this address never changes.") \
    X(S_RECV_KEYNOTE,           "signing key: macOS Keychain (encrypted at rest \xC2\xB7 this device only)") \
    /* ── Send screen ── */ \
    X(S_SEND_TITLE,             "Send") \
    X(S_SEND_BALANCE,           "balance") \
    X(S_SEND_TO_LABEL,          "to — address or name") \
    X(S_SEND_TO_PH,             "Pu… or a name") \
    X(S_SEND_PASTE,             "paste") \
    X(S_SEND_VALID_ADDR,        "\xE2\x9C\x93 valid address") \
    X(S_SEND_NAME_DEMO,         "\xE2\x9C\x93 name \xE2\x86\x92 PmXk4a…9qWdE") \
    X(S_SEND_NAME_RES_FMT,      "\xE2\x9C\x93 name \xE2\x86\x92 %s") \
    X(S_SEND_ERR_NOTPLAIN,      "that name's owner isn't a plain address") \
    X(S_SEND_ERR_NONAME,        "no such name on-chain") \
    X(S_SEND_ERR_ADDR_FMT,      "not a valid %s address or name") \
    X(S_SEND_AMOUNT,            "amount") \
    X(S_SEND_AVAIL_FMT,         "avail %s \xE2\xB1\xA3") \
    X(S_SEND_MAX,               "max") \
    X(S_SEND_FEE,               "network fee") \
    X(S_SEND_TOTAL,             "total") \
    X(S_SEND_ERR_AMT,           "not a valid amount") \
    X(S_SEND_ERR_DUST,          "below the 0.01 dust minimum") \
    X(S_SEND_ERR_SHORT_FMT,     "insufficient balance — short %s") \
    X(S_SEND_SEND,              "send") \
    X(S_SEND_SENT_FLASH,        "sent · pending ~1 min") \
    X(S_SEND_FOOT_DEMO,         "confirms on-chain in about a minute · pending until then") \
    X(S_SEND_FOOT_LIVE,         "signs with the dev key · broadcasts to the peer · confirms next block") \
    /* ── Settings screen ── */ \
    X(S_SET_TITLE,              "Settings") \
    X(S_SET_MODE,               "mode") \
    X(S_SET_DEMO_FIXTURES,      "demo fixtures") \
    X(S_SET_LIVE_CHAIN,         "live chain") \
    X(S_SET_HEIGHT,             "height") \
    X(S_SET_ENGINE,             "engine") \
    X(S_SET_STARTING,           "starting…") \
    X(S_SET_MESH_FMT,           "firehose · %d peer%s · %s zones") \
    X(S_SET_DNSMESH,            "dns mesh") \
    X(S_SET_RESOLVER,           "resolver") \
    X(S_SET_NOT_RUNNING,        "not running") \
    X(S_SET_PROXY_FMT,          "127.0.0.1:%d · %lld ok · %lld failed") \
    X(S_SET_DANEPROXY,          "DANE proxy") \
    X(S_SET_LASTREFUSED_FMT,    "last refused publish: %s") \
    X(S_SET_BROWSER_HDR,        "BROWSER ACCESS") \
    X(S_SET_ROOTCERT,           "root certificate") \
    X(S_SET_TRUSTED,            "trusted") \
    X(S_SET_NOT_INSTALLED,      "not installed") \
    X(S_SET_PRESENT,            "present") \
    X(S_SET_MISSING,            "missing") \
    X(S_SET_PORTREDIR,          "port redirect :443\xE2\x86\x92:" APP_PROXY_PORT_S) \
    X(S_SET_CONFIGURED,         "configured") \
    X(S_SET_NOT_CONFIGURED,     "not configured") \
    X(S_SET_ENABLE_WEB,         "Enable web access\xE2\x80\xA6") \
    X(S_SET_ENABLED_OK,         "enabled \xE2\x9C\x93") \
    X(S_SET_INSTALL_INC,        "install incomplete") \
    X(S_SET_UNINSTALL_WEB,      "Uninstall web access") \
    X(S_SET_REMOVED_OK,         "removed \xE2\x9C\x93") \
    X(S_SET_UNINSTALL_INC,      "uninstall incomplete") \
    X(S_SET_STARTUP_HDR,        "STARTUP") \
    X(S_SET_LOGIN,              "launch at login") \
    X(S_SET_LOGIN_SUB,          "starts hidden in the tray \xE2\x80\x94 resolver + proxy serve " \
                                APP_DOT_TLD " from login") \
    X(S_SET_PHRASE_HDR,         "RECOVERY PHRASE") \
    X(S_SET_BACKUP,             "backup") \
    X(S_SET_PHRASE_12,          "12-word recovery phrase") \
    X(S_SET_REVEAL,             "Reveal recovery phrase\xE2\x80\xA6") \
    X(S_SET_RESTORE,            "Restore\xE2\x80\xA6") \
    X(S_SET_DATA_HDR,           "DATA FOLDER") \
    X(S_SET_DATA_OPEN,          "Open folder") \
    X(S_SET_DATA_CHANGE,        "Change location\xE2\x80\xA6") \
    X(S_SET_DATA_MOVED_FMT,     "data location set to %s \xE2\x80\x94 restart to use it " \
                                "(a fresh sync starts there)") \
    /* ── Peers screen (view_peers.c; reached from the balance dropdown) ── */ \
    X(S_PEERS_TITLE,        "Peers") \
    X(S_PEERS_EMPTY_DEMO,   "peer data is live (demo has none)") \
    X(S_PEERS_CONNS_HDR,    "Connections") \
    X(S_PEERS_CONNS_FMT,    "%d up \xC2\xB7 %d mesh") \
    X(S_PEERS_COL_PEER,     "PEER") \
    X(S_PEERS_COL_AGENT,    "AGENT") \
    X(S_PEERS_COL_STATE,    "STATE") \
    X(S_PEERS_DIR_IN,       "in") \
    X(S_PEERS_DIR_OUT,      "out") \
    X(S_PEERS_ST_UP,        "up") \
    X(S_PEERS_ST_HANDSHAKE, "handshaking\xE2\x80\xA6") \
    X(S_PEERS_ST_DIALING,   "dialing\xE2\x80\xA6") \
    X(S_PEERS_ST_REDIAL_FMT,"redial in %llds") \
    X(S_PEERS_BADGE_MESH,   "MESH") \
    X(S_PEERS_BADGE_SEAT,   "SEAT") \
    X(S_PEERS_NO_AGENT,     "(no agent yet)") \
    X(S_PEERS_CONNS_EMPTY,  "no connections yet \xE2\x80\x94 the serve loop dials as peers turn up") \
    X(S_PEERS_WALK_HDR,     "Chain walk") \
    X(S_PEERS_WALK_STATUS,  "status") \
    X(S_PEERS_WALK_LIVE_FMT,"walking \xC2\xB7 dial %d / %d") \
    X(S_PEERS_WALK_IDLE,    "idle") \
    X(S_PEERS_WALK_NEVER,   "hasn't run yet") \
    X(S_PEERS_WALK_PASS,    "this pass") \
    X(S_PEERS_WALK_PASS_FMT,"%d dialed \xC2\xB7 %d answered \xC2\xB7 %d pepenet") \
    X(S_PEERS_WALK_PROBE,   "last probe") \
    X(S_PEERS_WALK_DOWN,    "no answer") \
    X(S_PEERS_WALK_FOUND,   "pepenet known") \
    X(S_PEERS_WALK_FOUND_FMT,"%d peer%s") \
    X(S_PEERS_WALK_LAST,    "last pass") \
    X(S_PEERS_WALK_LAST_FMT,"%s ago \xC2\xB7 %lld total") \
    X(S_PEERS_WALK_START,   "start walk") \
    X(S_PEERS_WALK_STOP,    "stop") \
    X(S_PEERS_WALK_QUEUED,  "queued \xE2\x80\xA6") \
    X(S_PEERS_WALK_GATED,   "connected to a pepenet peer \xE2\x80\x94 nothing to hunt") \
    /* ── per-name SSL screen (view_ssl.c) ── */ \
    X(S_SSL_WHICH,          "SSL") \
    X(S_SSL_LINK_DNS,       "DNS \xE2\x80\xBA") \
    X(S_SSL_EMPTY_NONAME,   "register a name to issue certificates") \
    /* ── SSL certificate entry card ── */ \
    X(S_SSL_ROLE_DEFAULT,   "DEFAULT \xC2\xB7 COVERS ALL") \
    X(S_SSL_ROLE_APEX,      "APEX ONLY") \
    X(S_SSL_ROLE_SUB,       "SUBDOMAIN \xC2\xB7 SEPARATE KEY") \
    X(S_SSL_EXPORT,         "Export bundle") \
    X(S_SSL_DELETE,         "Delete\xE2\x80\xA6") \
    X(S_SSL_WILD_FMT,       "cover subdomains \xC2\xB7 *.%s" APP_DOT_TLD) \
    X(S_DLG_SSLDEL_TITLE,   "Delete certificate") \
    X(S_DLG_SSLDEL_BODY,    "removes the certificate and its private key from this " \
                            "machine. a site serving with this key can't be verified " \
                            "once its pin is gone \xE2\x80\x94 this can't be undone.") \
    X(S_DLG_SSLDEL_UNPIN,   "also remove the published TLSA pin") \
    X(S_DLG_SSLDEL_OK,      "Delete") \
    X(S_SSL_ORPHAN_FMT,     "pin published for %s \xE2\x80\x94 no certificate on " \
                            "this machine") \
    X(S_SSL_UNPIN,          "Remove pin") \
    X(S_SSL_PINNED_OK,      "pinned \xE2\x80\x94 the mesh TLSA matches this key") \
    X(S_SSL_PIN_MISMATCH_FMT, "the TLSA pins a DIFFERENT key \xE2\x80\x94 republish") \
    X(S_SSL_PIN_MISSING_FMT, "not pinned yet \xE2\x80\x94 %s" APP_DOT_TLD " won't validate until you publish") \
    X(S_SSL_REPUBLISH,      "republish") \
    X(S_SSL_PUBLISH_PIN,    "publish pin") \
    X(S_SSL_KEYPIN_LABEL,   "KEY PIN (TLSA 3 1 1)") \
    X(S_SSL_COPY,           "\xE2\xA7\x89 copy") \
    X(S_SSL_KIND_SELF,      "self-signed \xC2\xB7 DANE") \
    X(S_SSL_KEY_ALGO,       "ECDSA P-256") \
    X(S_SSL_CREATED_FMT,    "created %s") \
    X(S_SSL_VALIDITY,       "valid ~10 years") \
    /* ── SSL empty state (9e): Create panel ── */ \
    X(S_SSL_EMPTY_TITLE,    "no certificate yet") \
    X(S_SSL_EMPTY_BODY_FMT, "create one to make %s" APP_DOT_TLD \
                            " servable over https \xE2\x80\x94 pinned to your name, no CA") \
    X(S_SSL_CREATE_TITLE,   "Create certificate") \
    X(S_SSL_CREATE_BODY,    "generate a P-256 key and self-signed cert. it covers the apex " \
                            "and every subdomain.") \
    X(S_SSL_COVERS,         "COVERS") \
    X(S_SSL_CREATE_NOTE,    "the final step publishes the TLSA pin to the mesh \xE2\x80\x94 that is " \
                            "what makes the padlock trustless.") \
    X(S_SSL_CREATE,         "Create") \
    X(S_SSL_GEN_FAILED,     "generate failed") \
    /* ── SSL certificate list (9d) ── */ \
    X(S_SSL_CERTS_TITLE,    "Certificates") \
    X(S_SSL_NCERTS_FMT,     "%d \xC2\xB7 self-signed, pinned by DANE") \
    X(S_SSL_ADD_SUB,        "+ certificate for a subdomain") \
    X(S_SSL_ADD_SUB_BODY,   "a separate key for a sub hosted elsewhere \xE2\x80\x94 contains the " \
                            "blast radius if that host is compromised") \
    X(S_SSL_ADD_BTN,        "add") \
    /* ── SSL pin-status legend & footers ── */ \
    X(S_SSL_LEGEND,         "PIN STATUS") \
    X(S_SSL_LEG_PINNED,     "pinned") \
    X(S_SSL_LEG_UNPINNED,   "not pinned yet") \
    X(S_SSL_LEG_MISMATCH,   "key mismatch \xE2\x80\x94 republish") \
    X(S_SSL_DEMO_NOTE,      "certificates are live data (demo has none)") \
    /* ── shared across dialogs ── */ \
    X(S_DLG_CANCEL,             "Cancel") \
    X(S_DLG_WHY_SHORT_FMT,      "insufficient balance — short %s") \
    X(S_DLG_WHY_QUEUED,         "an op for this name is already queued — wait for the next block") \
    X(S_DLG_WHY_MOVELOCK,       "movement-locked — only renew works right now") \
    X(S_DLG_WHY_BADADDR_FMT,    "not a valid %s address") \
    X(S_DLG_WHY_OWNADDR,        "that's this wallet's own address") \
    X(S_DLG_WHY_BADPRICE,       "not a valid price") \
    X(S_DLG_WHY_NORATE,         "still syncing — the live rate isn't known yet") \
    X(S_DLG_WHY_PREACT_FMT,     "names activate at block %s \xE2\x80\x94 ~%lld min to go") \
    X(S_DLG_FEE,                "network fee") \
    X(S_DLG_FEE_ONETX,          "network fee (one tx)") \
    X(S_DLG_TOTAL,              "total") \
    X(S_DLG_TO_ADDR,            "to address") \
    X(S_DLG_PRICE,              "price") \
    X(S_DLG_DAYS,               "days") \
    X(S_DLG_MAX,                "max") \
    X(S_DLG_ADDR_PH,            "Pu…") \
    X(S_DLG_TITLE_BUY,          "buy") \
    X(S_DLG_TITLE_RECLAIM,      "reclaim") \
    X(S_DLG_LIST_PRICE,         "list price") \
    X(S_DLG_TIMER_BUY,          "to complete purchase") \
    X(S_DLG_BUY_OK,             "Buy") \
    /* ── renew dialog (DLG_RENEW) ── */ \
    X(S_DLG_RENEW_TITLE,        "renew") \
    X(S_DLG_RENEW_WHY_RESERVED, "a buyer reserved this name — wait out the window") \
    X(S_DLG_RENEW_EXPIRES,      "expires now") \
    X(S_DLG_RENEW_ADD,          "add") \
    X(S_DLG_RENEW_ATCAP,        "at the 365-day cap — nothing to add") \
    X(S_DLG_RENEW_CAP_FMT,      "you can add at most %dd") \
    X(S_DLG_RENEW_COST,         "cost") \
    X(S_DLG_RENEW_OK,           "Renew") \
    /* ── batch renew dialog (DLG_BATCH_RENEW) ── */ \
    X(S_DLG_BRENEW_WHY_NONE,    "nothing renewable in the selection") \
    X(S_DLG_BRENEW_TITLE_FMT,   "renew %d name%s") \
    X(S_DLG_BRENEW_CAP_NOTE,    "\xE2\x86\x92 365d cap") \
    X(S_DLG_BRENEW_PLUSD_FMT,   "+%dd") \
    X(S_DLG_BRENEW_TOTAL_FMT,   "total · %d name%s") \
    X(S_DLG_BRENEW_OK_FMT,      "Renew all %d") \
    /* ── sell dialog (DLG_SELL) ── */ \
    X(S_DLG_SELL_TITLE,         "sell") \
    X(S_DLG_SELL_WHY_DUST,      "price below 2.0 — its 0.5% pay-leg would be dust") \
    X(S_DLG_SELL_WHY_SHORT,     "lease shorter than the window — renew first") \
    X(S_DLG_SELL_PRICE_PH,      "2.0 or more") \
    X(S_DLG_SELL_WINDOW,        "listing window") \
    X(S_DLG_SELL_LISTFOR,       "list for") \
    X(S_DLG_SELL_MAX30,         "max 30") \
    X(S_DLG_SELL_OK,            "List for sale") \
    /* ── offer dialog (DLG_OFFER) ── */ \
    X(S_DLG_OFFER_TITLE,        "offer") \
    X(S_DLG_OFFER_WHY_DUST,     "price below the 0.01 dust floor — the buyer couldn't pay") \
    X(S_DLG_OFFER_WHY_SHORT,    "lease shorter than the offer window — renew first") \
    X(S_DLG_OFFER_NOTE,         "only they can buy it \xC2\xB7 2 h to pay, then the offer lapses") \
    X(S_DLG_OFFER_OK,           "Make offer") \
    /* ── transfer dialog (DLG_TRANSFER) ── */ \
    X(S_DLG_TRANSFER_TITLE,     "transfer") \
    X(S_DLG_TRANSFER_OK,        "Transfer") \
    /* ── release dialog (DLG_RELEASE) ── */ \
    X(S_DLG_RELEASE_TITLE,      "release") \
    X(S_DLG_RELEASE_BODY,       "the name returns to the open pool immediately. anyone can claim it. " \
                                "remaining lease is not refunded.") \
    X(S_DLG_RELEASE_CANCEL,     "keep it") \
    X(S_DLG_RELEASE_OK,         "Release") \
    /* ── batch release dialog (DLG_BATCH_RELEASE) ── */ \
    X(S_DLG_BRELEASE_TITLE_FMT, "release %d name%s?") \
    X(S_DLG_BRELEASE_BODY,      "they return to the open pool immediately. anyone can claim them. " \
                                "remaining lease is not refunded.") \
    X(S_DLG_BRELEASE_CANCEL,    "keep them") \
    X(S_DLG_BRELEASE_OK_FMT,    "Release all %d") \
    /* ── batch transfer dialog (DLG_BATCH_TRANSFER) ── */ \
    X(S_DLG_BTRANSFER_TITLE_FMT,"transfer %d name%s") \
    X(S_DLG_BTRANSFER_NOTE,     "they move immediately and irreversibly — there is no acceptance " \
                                "step and no claw-back. the remaining lease conveys.") \
    X(S_DLG_BTRANSFER_OK_FMT,   "Transfer all %d") \
    /* ── claim dialog (DLG_CLAIM) ── */ \
    X(S_DLG_CLAIM_TITLE,        "claim a name") \
    X(S_DLG_CLAIM_WHY_SYNTAX,   "names are a-z 0-9 - and at most 32 bytes") \
    X(S_DLG_CLAIM_WHY_TAKEN,    "that name is taken") \
    X(S_DLG_CLAIM_NAME,         "name") \
    X(S_DLG_CLAIM_NAME_PH,      "yourname") \
    X(S_DLG_CLAIM_LEASEFOR,     "lease for") \
    X(S_DLG_CLAIM_BURN,         "lease burn") \
    X(S_DLG_CLAIM_FEES2,        "network fees (2 tx)") \
    X(S_DLG_CLAIM_NOTE,         "takes two transactions about a minute apart — we handle the wait for you.") \
    X(S_DLG_CLAIM_OK,           "Submit claim") \
    /* ── place bid dialog (DLG_BID) ── */ \
    X(S_DLG_BID_WHY_RESERVED,   "someone already reserved this name") \
    X(S_DLG_BID_WHY_CLOSED,     "the listing window closed") \
    X(S_DLG_BID_WHY_MINE_DUST,  "priced under 2.0 — un-executable; it unlists when the window closes") \
    X(S_DLG_BID_WHY_DUST,       "priced under 2.0 — its 0.5% pay-leg is dust, un-executable") \
    X(S_DLG_BID_DEP_MINE,       "deposit (1%) — 0.5% burns") \
    X(S_DLG_BID_DEP,            "deposit (1%) — non-refundable") \
    X(S_DLG_BID_REM_MINE,       "remainder · auto-settles to you") \
    X(S_DLG_BID_REM,            "remainder · settles automatically") \
    X(S_DLG_BID_FEES2,          "2 network fees") \
    X(S_DLG_BID_NOTE_MINE,      "settles by itself · 99.5% returns · nets ~0.5% + fees") \
    X(S_DLG_BID_WARN,           "the 1% deposit is spent even if another bid wins.") \
    X(S_DLG_BID_OK_MINE,        "Reclaim") \
    X(S_DLG_BID_OK,             "Place bid") \
    /* ── settle dialog (DLG_SETTLE) ── */ \
    X(S_DLG_SETTLE_WHY_EXPIRED, "the settle window expired — the deposit is forfeit") \
    X(S_DLG_SETTLE_WHY_DUST,    "un-executable — the remainder is below the 0.01 dust floor") \
    X(S_DLG_SETTLE_BADGE,       "RESERVED") \
    X(S_DLG_SETTLE_TIMER_MINE,  "to finish reclaiming") \
    X(S_DLG_SETTLE_PAID,        "- paid bid") \
    X(S_DLG_SETTLE_REM_MINE,    "remainder (self-paid)") \
    X(S_DLG_SETTLE_REM,         "remaining") \
    X(S_DLG_SETTLE_OK_MINE,     "Finish") \
    /* ── blocked double-reserve dialog (DLG_BLOCKED) ── */ \
    X(S_DLG_BLOCKED_TITLE,      "can't reserve") \
    X(S_DLG_BLOCKED_BODY_FMT,   "someone else already reserved this name (%s left in window).") \
    X(S_DLG_BLOCKED_NOTE_FMT,   "it frees up if they don't settle. we'll ping you — or check back in %s.") \
    X(S_DLG_BLOCKED_OK,         "Watch this name") \
    /* ── pay-an-offer dialog (DLG_PAYOFFER) ── */ \
    X(S_DLG_PAYOFFER_WHY_CLOSED,"the offer window closed") \
    X(S_DLG_PAYOFFER_WHY_DUST,  "un-executable offer — its price is below the 0.01 dust floor") \
    X(S_DLG_PAYOFFER_BODY,      "sold directly to you at a fixed price. pay before the window closes to take it.") \
    X(S_DLG_PAYOFFER_BADGE,     "OFFERED") \
    /* ── DNS record modal (DLG_DNS_REC) ── */ \
    X(S_DLG_DNSREC_TITLE_ADD,   "Add DNS record") \
    X(S_DLG_DNSREC_TITLE_EDIT,  "Edit record") \
    X(S_DLG_DNSREC_ERR_A,       "not a valid IPv4 address — each octet is 0–255") \
    X(S_DLG_DNSREC_ERR_AAAA,    "not a valid IPv6 address") \
    X(S_DLG_DNSREC_ERR_HOST,    "not a valid hostname") \
    X(S_DLG_DNSREC_ERR_MX,      "use: <priority> <host> — e.g. 10 mail.example") \
    X(S_DLG_DNSREC_ERR_TXT,     "text is over 255 bytes") \
    X(S_DLG_DNSREC_ERR_SRV,     "SRV rdata is raw hex here (wire format)") \
    X(S_DLG_DNSREC_ERR_SSHFP,   "use: <algo> <fptype> <hex>") \
    X(S_DLG_DNSREC_ERR_HEX,     "expects hex rdata") \
    X(S_DLG_DNSREC_MORE,        "more…") \
    X(S_DLG_DNSREC_HOST_PH,     "@ (apex) or a sub") \
    X(S_DLG_DNSREC_TXT_PH,      "\"text\"") \
    X(S_DLG_DNSREC_VAL_PH,      "value") \
    X(S_DLG_DNSREC_PREVIEW,     "PREVIEW") \
    X(S_DLG_DNSREC_BYTES_OVER_FMT, "record is ~%d bytes \xC2\xB7 over 80 gossips fine, only the " \
                                "on-chain fallback is skipped") \
    X(S_DLG_DNSREC_BYTES_FMT,   "record is ~%d bytes") \
    X(S_DLG_DNSREC_DELETE,      "Delete") \
    X(S_DLG_DNSREC_SAVE,        "Save") \
    X(S_DLG_DNSREC_ADD,         "Add record") \
    /* ── subdomain certificate dialog (DLG_SSL_SUB) ── */ \
    X(S_DLG_SSLSUB_TITLE,       "Certificate for a subdomain") \
    X(S_DLG_SSLSUB_BODY,        "a separate key for a sub hosted elsewhere — if that host is " \
                                "compromised, only this key leaks.") \
    X(S_DLG_SSLSUB_LABEL,       "SUBDOMAIN") \
    X(S_DLG_SSLSUB_PH,          "shop") \
    X(S_DLG_SSLSUB_ERR,         "lowercase letters, digits, - and . only") \
    X(S_DLG_SSLSUB_NOTE_FMT,    "its pin publishes at _443._tcp.%s automatically") \
    X(S_DLG_SSLSUB_TOKEN,       "<sub>") \
    X(S_DLG_SSLSUB_OK,          "Create") \
    /* ── first-run consent dialog (DLG_CONSENT) ── */ \
    X(S_DLG_CONSENT_TITLE,      "Access " APP_NET_LABEL "?") \
    X(S_DLG_CONSENT_PROMISE,    "this lets you visit " APP_DOT_TLD " websites. to do so, we:") \
    X(S_DLG_CONSENT_S1,         "Install the " APP_DOT_TLD " certificate") \
    X(S_DLG_CONSENT_S1_SUB,     "a local trustless certificate authority for " APP_DOT_TLD " only") \
    X(S_DLG_CONSENT_S2,         "Run the DNS mesh") \
    X(S_DLG_CONSENT_S2_SUB,     "answers " APP_DOT_TLD " lookups on this machine") \
    X(S_DLG_CONSENT_S3,         "Run the local proxy") \
    X(S_DLG_CONSENT_S3_SUB,     "enables secure https for " APP_DOT_TLD " sites") \
    X(S_DLG_CONSENT_SKIP,       "Skip for now") \
    X(S_DLG_CONSENT_SKIP_SUB,   "wallet & names work without it") \
    X(S_DLG_CONSENT_ENABLE,     "Enable web access") \
    X(S_DLG_CONSENT_ENABLED,    "web access enabled \xE2\x9C\x93") \
    X(S_DLG_CONSENT_INCOMPLETE, "install incomplete — see Settings") \
    /* ── single-writer lock dialog (DLG_LOCKED) ── */ \
    X(S_DLG_LOCKED_TITLE,       "wallet database is in use") \
    X(S_DLG_LOCKED_BODY,        "App already open.") \
    X(S_DLG_LOCKED_QUIT,        "Quit") \
    X(S_DLG_LOCKED_RETRY,       "Retry") \
    /* ── first-run backup nag (DLG_BACKUP) ── */ \
    X(S_DLG_BACKUP_TITLE,       "Back up your 12 words \xE2\x80\x94 now") \
    X(S_DLG_BACKUP_BODY,        "this wallet was just created and exists only on this Mac. its 12-word " \
                                "recovery phrase is the ONLY way to get your coins and names back if the " \
                                "machine is lost or the keychain breaks \xE2\x80\x94 no server has a copy, " \
                                "and nobody can reset it for you.") \
    X(S_DLG_BACKUP_HINT,        "write the words on paper, in order. never a screenshot, a file, or the clipboard.") \
    X(S_DLG_BACKUP_SHOW,        "Show my 12 words") \
    X(S_DLG_BACKUP_LATER,       "Later") \
    X(S_DLG_BACKUP_SUB,         "you can reveal them anytime in Settings") \
    /* ── recovery phrase dialog (DLG_REVEAL_PHRASE) ── */ \
    X(S_DLG_PHRASE_TITLE,       "Recovery phrase") \
    X(S_DLG_PHRASE_BODY,        "write these 12 words down and keep them offline. anyone who has them " \
                                "controls this wallet; without them a lost device cannot be recovered.") \
    X(S_DLG_PHRASE_DONE,        "Done \xE2\x80\x94 I wrote it down") \
    /* ── restore-from-phrase dialog (DLG_RESTORE_PHRASE) ── */ \
    X(S_DLG_RESTORE_TITLE,      "Restore from phrase") \
    X(S_DLG_RESTORE_BODY,       "type your 12-word recovery phrase to replace this wallet. this overwrites " \
                                "the current key \xE2\x80\x94 be sure it is backed up first.") \
    X(S_DLG_RESTORE_LABEL,      "RECOVERY PHRASE") \
    X(S_DLG_RESTORE_PH,         "abandon abandon abandon … about") \
    X(S_DLG_RESTORE_HINT,       "12 words, separated by spaces.") \
    X(S_DLG_RESTORE_VALID,      "valid recovery phrase \xE2\x9C\x93") \
    X(S_DLG_RESTORE_INVALID,    "not a valid 12-word phrase yet") \
    X(S_DLG_RESTORE_ERR,        "could not restore from that phrase") \
    X(S_DLG_RESTORE_OK,         "Restore") \
    X(S_DLG_RESTORE_DONE_TITLE, "Wallet restored") \
    X(S_DLG_RESTORE_DONE_BODY,  "the recovery phrase is now this wallet. restart PepeNet so the chain " \
                                "reloads balances for the restored address.") \
    X(S_DLG_RESTORE_DONE_OK,    "Done") \
    /* ── tray menu (tray.m) ── */ \
    X(S_TRAY_WEB_ON,        "Web: on \xE2\x80\x94 " APP_DOT_TLD " resolving") \
    X(S_TRAY_WEB_OFF,       "Web: off") \
    X(S_TRAY_CHAIN_UNREACH, "Chain: peer unreachable") \
    X(S_TRAY_CHAIN_STARTING,"Chain: starting\xE2\x80\xA6") \
    X(S_TRAY_CHAIN_FMT,     "Chain: %s \xC2\xB7 block %s") \
    X(S_TRAY_FEE_FMT,       "Fee: %s " APP_COIN_GLYPH " / tx") \
    X(S_TRAY_RENT_FMT,      "Rent: %s " APP_COIN_GLYPH " / name\xC2\xB7yr") \
    X(S_TRAY_MESH_FMT,      "Mesh: %d peer%s") \
    X(S_TRAY_MESH_STARTING, "Mesh: starting\xE2\x80\xA6") \
    X(S_TRAY_OPEN,          "Open " APP_NAME) \
    X(S_TRAY_QUIT,          "Quit " APP_NAME) \
    /* ── op-queue labels (ops.c — status footer / dialogs) ── */ \
    X(S_OPS_LBL_SEND,               "send") \
    X(S_OPS_LBL_CLAIM_FMT,          "claim '%s'") \
    X(S_OPS_LBL_COMMIT_FMT,         "commit '%s'") \
    X(S_OPS_LBL_RENEW,              "renew") \
    X(S_OPS_LBL_RENEW_ONE_FMT,      "renew '%s'") \
    X(S_OPS_LBL_RENEW_N_FMT,        "renew %d names") \
    X(S_OPS_LBL_TRANSFER_ALL,       "transfer all") \
    X(S_OPS_LBL_TRANSFER_ONE_FMT,   "transfer '%s'") \
    X(S_OPS_LBL_TRANSFER_N_FMT,     "transfer %d names") \
    X(S_OPS_LBL_LIST_FMT,           "list '%s'") \
    X(S_OPS_LBL_RELEASE_ONE_FMT,    "release '%s'") \
    X(S_OPS_LBL_RELEASE_N_FMT,      "release %d names") \
    X(S_OPS_LBL_OFFER_FMT,          "offer '%s'") \
    X(S_OPS_LBL_RESERVE_FMT,        "reserve '%s'") \
    X(S_OPS_LBL_SETTLE_FMT,         "settle '%s'") \
    X(S_OPS_LBL_BUY_FMT,            "buy '%s'") \
    X(S_OPS_LBL_TXCHAIN,            "tx chain") \
    X(S_OPS_LBL_CONFIRMATION,       "confirmation") \
    /* ── op-queue hold reasons (ops.c — why the head waits) ── */ \
    X(S_OPS_HOLD_RELAY_CAP_FMT,     "chain at the %d-tx relay cap \xE2\x80\x94 next block") \
    X(S_OPS_HOLD_UNCONFIRMED,       "chain unconfirmed for 30 min \xE2\x80\x94 holding new txs") \
    X(S_OPS_HOLD_NAME_INFLIGHT_FMT, "'%s' has a tx in flight \xE2\x80\x94 next block") \
    X(S_OPS_HOLD_ANCHORS_SET,       "this op anchors the name set \xE2\x80\x94 waiting for pending name changes") \
    X(S_OPS_HOLD_BCAST_RETRY,       "broadcast failed \xE2\x80\x94 retrying shortly") \
    /* ── op-queue errors (ops.c) ── */ \
    X(S_OPS_ERR_TOO_MANY_CLAIMS,    "too many claims waiting on commits \xE2\x80\x94 open claim again once one lands") \
    X(S_OPS_ERR_TOO_MANY_RESERVES,  "too many reserves waiting to settle \xE2\x80\x94 settle this one from the Market screen") \
    X(S_OPS_ERR_WORKER_START,       "could not start the wallet worker") \
    X(S_OPS_ERR_KEY_UNAVAILABLE,    "wallet key unavailable") \
    X(S_OPS_ERR_CHAIN_DIVERGED,     "the tx chain diverged from the chain db \xE2\x80\x94 holding; " \
                                    "restart the app if this persists") \
    X(S_OPS_ERR_REBUILT_FMT,        "a tx confirmed under a different txid \xE2\x80\x94 rebuilding %d op%s " \
                                    "on the confirmed view") \
    X(S_OPS_ERR_LOST_FMT,           "a signed tx never reached the network \xE2\x80\x94 rebuilding %d op%s " \
                                    "and resending") \
    X(S_OPS_GATE_NO_KEY,            "wallet key unavailable \xE2\x80\x94 check the launch log") \
    X(S_OPS_GATE_QUEUE_FULL,        "the op queue is full \xE2\x80\x94 wait for the next block") \
    X(S_OPS_ERR_STALE_30MIN,        "the tx chain hasn't confirmed in 30 min \xE2\x80\x94 " \
                                    "balance may read low until it folds") \
    X(S_OPS_ERR_COMMIT_TIMEOUT,     "the commit hasn't appeared in 30 min \xE2\x80\x94 open claim again to retry") \
    X(S_OPS_ERR_RESERVE_TIMEOUT,    "the reserve hasn't folded in 30 min \xE2\x80\x94 if it lands, " \
                                    "settle from the Market screen (the window is 5 h)") \
    X(S_OPS_ERR_OUTBID_FMT,         "outbid \xE2\x80\x94 another reserve won '%s'; the deposit is spent") \
    X(S_OPS_ERR_NOT_RESERVABLE_FMT, "'%s' is no longer reservable \xE2\x80\x94 the listing ended before " \
                                    "the reserve folded") \
    /* ── end of table ── */

typedef enum {
#define X(id, s) id,
    DNET_STRINGS(X)
#undef X
    S__COUNT
} StrId;

// the lookup — today always the English table; a locale switch goes in
// ui_str, nowhere else
const char *ui_str(StrId id);
#define TR(id) ui_str(id)

#endif
