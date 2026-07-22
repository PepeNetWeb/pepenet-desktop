// ui.h — screen router + all interaction state.
//
// One window, one canvas (design/screens.html). Three sections — Discover
// (home) · My Names · Name Market — are TABS on a persistent strip under the
// titlebar; the balance chip (right end of the strip) drops down the wallet
// verbs + live health rows + Settings. DNS and SSL are PER-NAME screens
// reached from a My Names row (‹ back returns there, with a cross-link
// between the two). Dialogs are modal cards over a scrim; dropdowns are
// anchored panels that close on outside click. A status footer carries the
// op readout + sync pulse.
#ifndef DNET_UI_H
#define DNET_UI_H

#include "nk_config.h"
#include "draw.h"
#include "strings.h"
#include "../model.h"

#include <stddef.h>

// per-tx network fee shown in dialogs, koinu — model_fee_k(): the relay floor
// (0.001) in demo / while syncing, the engine's recent-window Q3 quote live
// (fee.h). A macro so every "+ fee" total and gate stays one source; ops.c
// attaches the same call's result, so what a dialog shows is what the tx pays.
#define UI_FEE_K model_fee_k()

// §5 executability: a market op's SPENDABLE legs must clear the host
// network's dust floor (0.01) or the tx will not relay — the fold would honor
// it, but no standard node ever mines it. The binding leg is the 0.5% RESERVE
// pay-leg, so the lowest executable listing price is 200 × dust = 2.0; a
// directed offer pays full price in one output, so its floor is dust itself.
// Clients MUST NOT surface or originate ops below these (protocol-spec §5).
#define UI_DUST_K      1000000LL           // wallet.c DUST — Doge-family 0.01
#define UI_LIST_MIN_K  (200 * UI_DUST_K)   // min executable SELL price (2.0)

// the consensus name test — the REAL protocol function (state.c, linked in via
// the indexer's fold): [a-z0-9_.], 1..20 bytes, no case-folding
int sm_name_valid(const char *name, size_t len);

typedef enum {
    V_DISCOVER, V_NAMES, V_MARKET, V_RECEIVE, V_SEND, V_DNS, V_SSL, V_PEERS,
    V_SETTINGS
} View;

typedef enum {
    DLG_NONE,
    DLG_RENEW,          // single-name renew, 365d cap enforced
    DLG_BATCH_RENEW,    // the "Renew N" bar dialog
    DLG_SELL,           // price + listing window
    DLG_OFFER,          // §3.7 SELL_TO: directed offer — buyer + price, 2 h window
    DLG_TRANSFER,
    DLG_RELEASE,        // destructive confirm
    DLG_BATCH_RELEASE,  // the "Release K" bar dialog — one bitmap tx
    DLG_BATCH_TRANSFER, // the "Transfer K" bar dialog — one bitmap tx, one target
    DLG_CLAIM,          // claim wizard (single dialog, two-tx cost)
    DLG_BID,            // reserve = 1% non-refundable deposit warning
    DLG_SETTLE,         // RESERVED countdown → pay remainder
    DLG_BLOCKED,        // double-reserve prevented
    DLG_PAYOFFER,       // offer-to-me confirm
    DLG_DNS_REC,        // add/edit-record modal (9f/9g) — UI.dnsm_edit picks
    DLG_DNS_CLEAR,      // whole-zone clear (destructive confirm; free op)
    DLG_SSL_SUB,        // per-subdomain certificate (9d "+ certificate…")
    DLG_SSL_DEL,        // delete a certificate (destructive confirm + unpin)
    DLG_CONSENT,        // first-run web-access consent (9h)
    DLG_BACKUP,         // first-run backup nag — a fresh wallet's 12 words
    DLG_REVEAL_PHRASE,  // show the 12-word recovery phrase (sensitive)
    DLG_RESTORE_PHRASE, // type a 12-word phrase to restore the wallet
    DLG_LOCKED          // <coin>.db held by another desktop — Retry / Quit
} Dialog;

typedef enum { POP_NONE, POP_BALANCE, POP_NAMES_MORE } Popup;

typedef struct {
    View view;
    View last_tab;                  // most recent tab view — ‹ back's target
    Dialog dialog;
    Popup popup;
    struct nk_rect pop_anchor;      // trigger rect of the open popup
    int  pop_guard;                 // opening click must not count as "outside"

    // dialogs — steppers & fields
    int64_t burn_koinu;             // reserved for weight-style steppers
    int     renew_days;
    int     claim_days;
    char    claim_name[64];
    int     claim_name_len;
    int     name_target;            // index into M.names
    int     listing_target;         // index into M.listings
    int     offer_target;
    char    sell_price[24];  int sell_price_len;
    int     sell_days;

    // names screen
    unsigned sel_mask;              // checkbox selection
    int renew_sel;                  // batch renew scope: 1 = the selection
                                    // (selective bitmap), 0 = whole set (bare)
    int name_expanded;              // row with single-actions open, -1 none
    DkScroll sc_names;
    char names_q[64]; int names_q_len;

    // market
    DkScroll sc_market;
    char market_q[64]; int market_q_len;

    // discover (home)
    DkScroll sc_dir;
    char dir_q[64]; int dir_q_len;

    // peers screen
    DkScroll sc_peers;

    // settings
    DkScroll sc_set;

    // per-name DNS / SSL screens
    DkScroll sc_dns, sc_ssl;
    int  dns_name_sel;              // index into owned M.names (-1 none)
    int  web_busy;                  // frames left on an install/generate note
    char web_note[96];

    // add/edit-record modal (DLG_DNS_REC, 9f/9g)
    int  dnsm_edit;                 // 0 = add, 1 = edit (delete lives here)
    int  dnsm_type_sel;             // index into the modal type chip list
    int  dnsm_more;                 // extended type chips revealed
    char dnsm_host[64];  int dnsm_host_len;    // "@" or a sub label
    char dnsm_ttl[8];    int dnsm_ttl_len;
    char dnsm_val[512];  int dnsm_val_len;
    char dnsm_orig_label[64];       // edit: the record being overwritten…
    int  dnsm_orig_type;            // …deleted first if host/type changed

    // subdomain-certificate dialog (DLG_SSL_SUB)
    char ssl_sub[48]; int ssl_sub_len;
    // create panel: wildcard SAN choice, INVERTED so zero-init = wildcard on
    int  ssl_no_wild;
    // delete-certificate dialog (DLG_SSL_DEL)
    char ssl_del_host[64];          // TLD-less host whose cert dies
    int  ssl_del_keep_pin;          // leave the published TLSA up (default no)

    // first-run backup nag: init() queues it for a freshly-minted wallet; it
    // takes the stage on the first frame with no other modal up (consent/lock
    // go first), then never again this launch
    int  backup_pending;

    // recovery-phrase dialogs (DLG_REVEAL_PHRASE / DLG_RESTORE_PHRASE)
    char restore_buf[256]; int restore_len;   // typed 12-word phrase
    char restore_msg[160];      // "" idle · "!…" error
    int  restore_done;          // 1 = restore succeeded (show restart note)

    // send
    char send_to[80];  int send_to_len;
    char send_amt[24]; int send_amt_len;
    int  send_flash;                // frames left on the "sent · pending" note

    // demo banner dismissed
    int demo_note_off;
} Ui;

extern Ui UI;

void ui_frame(struct nk_context *ctx, float W, float H);
float app_px_scale(void);          // logical→device pixel factor (main.c)

// screens (view_*.c)
void view_discover(struct nk_context *ctx, struct nk_rect area);
void view_names(struct nk_context *ctx, struct nk_rect area);
void view_market(struct nk_context *ctx, struct nk_rect area);
void view_receive(struct nk_context *ctx, struct nk_rect area);
void view_send(struct nk_context *ctx, struct nk_rect area);
void view_dns(struct nk_context *ctx, struct nk_rect area);
void view_ssl(struct nk_context *ctx, struct nk_rect area);
void view_peers(struct nk_context *ctx, struct nk_rect area);
void view_settings(struct nk_context *ctx, struct nk_rect area);

// overlays
void popups_draw(struct nk_context *ctx, struct nk_rect screen);
void dialogs_draw(struct nk_context *ctx, struct nk_rect screen);

// shared bits (widgets.c)
void ui_screen_header(struct nk_context *ctx, struct nk_rect area,
                      const char *title);
// per-name plumbing shared by the DNS/SSL screens + the record modal
// (zone_rec comes through model.h → dnsnet.h → zone.h)
int  ui_dns_pick_name(void);                       // → M.names index, -1 none
void ui_rdata_str(const zone_rec *r, char *out, size_t cap);
int  ui_dnsm_type_from_code(int code);             // wire type → modal chip index
void ui_ssl_dirty(void);                           // certs changed — rescan now
// per-name screen sub-header (9c/9d): ‹ back → My Names · name + TLD ·
// "· <which>" · cross-link at the right edge. Returns the y below it.
float ui_name_header(struct nk_context *ctx, struct nk_rect area,
                     const char *name, const char *which,
                     const char *other_label, View other_view);
int  ui_balance_chip(struct nk_context *ctx, float xr, float cy);  // → clicked
void ui_sync_line(char *out, size_t cap);
int  ui_edit(struct nk_context *ctx, struct nk_rect r, char *buf, int *len, int max,
             const char *placeholder, ThemeFont f, int bare);      // → committed
                                                                   // bare: caller drew the card
void ui_popup_open(Popup p, struct nk_rect anchor);                // sets the open-click guard
void ui_btn_disabled(struct nk_context *ctx, struct nk_rect r, ThemeFont f,
                     const char *label);                           // inert, unmistakably dead
int  ui_toggle(struct nk_context *ctx, struct nk_rect r, int on);  // → clicked (caller flips)
void ui_kv_row(struct nk_context *ctx, float x, float xr, float y,
               const char *k, const char *v, struct nk_color kc, struct nk_color vc);
int  ui_stepper(struct nk_context *ctx, struct nk_rect r, char *valbuf,
                ThemeFont f, struct nk_color valcol);              // -1/0/+1

#endif
