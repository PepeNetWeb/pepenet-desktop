// appconf.h — THE instance configuration. Everything that makes this build
// "PepeNet on Pepecoin" lives in this one file: brand strings, the web TLD,
// the coin id, network endpoints, ports, and the theme palette. Standing up
// the same app on another host chain (Dogecoin, a testnet, …) = swapping
// this single file and rebuilding — no other source file names the instance.
//
// Rules for keeping it that way:
//   - no string literal containing the TLD, coin id, app name, or a port
//     number anywhere outside this header (grep-clean: "pepe", "PepeNet");
//   - colors are raw 0xRRGGBB here; theme.h turns them into nk_color macros;
//   - the coin id keys the DATA FILES (<coin>.db, wallet-<coin>.key,
//     dns-<coin>.db) and the base58 version table (wallet.c) — it is a
//     different knob from the display TLD on purpose (files stay "pep"
//     while the web suffix reads ".pepe").
#ifndef DNET_APPCONF_H
#define DNET_APPCONF_H

// ── identity ─────────────────────────────────────────────────────────────────
#define APP_NAME        "PepeNet"       // window title, titlebar brand, tray menu
#define APP_TRAY_ICON   "pepenet-tray.png"   // menu-bar face: the logo, cut to
                                             // 36px (@2x of the 18pt art box)
#define APP_TRAY_FACE   "\xF0\x9F\x90\xB8"   // 🐸 fallback face when the icon
                                             // resource is missing (dev runs)
#define APP_NET_LABEL   "the PepeNet"   // consent card: "Access the PepeNet?"
#define APP_BUNDLE_ID   "com.pepenet.app"  // launch-agent label; CMake's
                                                // MACOSX_BUNDLE_GUI_IDENTIFIER
                                                // must stay in sync

// ── storage ──────────────────────────────────────────────────────────────────
// The per-user data directory NAME (a dotfolder under $HOME by default):
// ~/.<APP_DATA_DIR>. The base protocol default is "pepenet"; this instance
// overrides it to keep each build's data separate. A runtime override (an
// absolute path chosen in Settings) supersedes this — see platform_data_dir.
#define APP_DATA_DIR    "pepenet"       // → ~/.pepenet

// ── chain ────────────────────────────────────────────────────────────────────
#define APP_COIN        "pep"           // coin id: data files + base58 table key
#define APP_COIN_GLYPH  "\xE2\xB1\xA3"  // Ᵽ U+2C63 (needs a face merge, theme.c)
#define APP_SEED_PEER   "pepenet.pepenet.com"  // preferred chain-sync peer AND the serve
                                        // loop's first dial. The indexer falls through
                                        // to cached last-good peers + the chain's DNS
                                        // seeds when it's down. On the machine the name
                                        // points AT, the self-connect guard drops it
                                        // (idx_self_seed) and addrman-style selection
                                        // (chain_topup) keeps ~8 outbound peers instead;
                                        // pin an explicit upstream with conf `peer=` if
                                        // ever needed.
#define APP_CHAIN_AGENT IDX_DNET_MARK "desktop:0.1/"  // our P2P subver — the
                                        // IDX_DNET_MARK prefix ("/pepenet-",
                                        // CMakeLists) is the mesh's discovery
                                        // mark (peer-discovery design)

// ── web plane ────────────────────────────────────────────────────────────────
#define APP_TLD         "pepe"          // the DNS suffix: <name>.pepe
#define APP_DOT_TLD     "." APP_TLD     // ".pepe" (literal-concat convenience)
// (the dns mesh rides the CHAIN wire now — dn* commands over the chain P2P
// connection on APP_SEED_PEER's port — so there is no separate mesh peer/port)
#define APP_DNS_PORT    15353           // local resolver, 127.0.0.1
#define APP_PROXY_PORT  8443            // local DANE proxy, 127.0.0.1
#define APP_PAC_PORT    8444            // PAC + CONNECT front door (Windows —
                                        // the DNS-leak-blocker-proof browser path)
#define APP_DNS_PORT_S   "15353"        // string twins for command lines
#define APP_PROXY_PORT_S "8443"
#define APP_PAC_PORT_S   "8444"
// pf anchor name — MUST mirror install-helper.sh's "pepenet-$TLD" (the helper
// derives it from its <tld> argument; this macro is the probe's side)
#define APP_PF_ANCHOR   "pepenet-" APP_TLD

// ── theme palette (design/screens.html §1a — swamp dark, flat only) ──────────
#define TH_BG        0x191A16   // window background
#define TH_FOOTER    0x15170F   // status-footer strip (one step below bg)
#define TH_PANEL     0x21231B   // raised cards, dialogs, menus
#define TH_INPUT     0x292C21   // inputs; hover = one step up from panel
#define TH_PRESS     0x313526   // pressed step above input
#define TH_BORDER    0x363A2C   // standard 1px border
#define TH_HAIR      0x23261D   // hairline row/section dividers
#define TH_TEXT      0xE9EFD8   // primary text (also the QR card cream)
#define TH_DIM       0x9FA887   // secondary text
#define TH_FADE3     0x767D63   // expiry fade step 3
#define TH_GHOST     0x515742   // faint text / expiry fade step 4
#define TH_ACCENT    0x77C25B   // accent green: money actions, active tab
#define TH_OK        0x9CB856   // olive: ok, owned, online, servable
#define TH_RED       0xD97757   // red: danger, expiring, destructive
#define TH_ONFILL    0x191A16   // text on an accent/olive/red fill
// tinted strips (pin status, notes): fill is (color, alpha/255), border solid
#define TH_TINT_OK_BR   0x4A5C39
#define TH_TINT_ACC_BR  0x4D6B39
#define TH_TINT_RED_BR  0x6B4A3E
// identicon content colors (Discover card art)
#define TH_ID_BLUE   0x7FA9D6
#define TH_ID_PURPLE 0xB98AD0
#define TH_ID_TAN    0xC58F6A

#endif
