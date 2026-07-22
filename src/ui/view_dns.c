// view_dns.c — the per-name DNS screen (9c): the record table for ONE owned
// name, reached from a My Names row. Edit = overwrite (delete lives inside
// the edit modal); the `_443._tcp*` TLSA rows are system-managed — greyed
// here, owned by the SSL page. The `_site` TXT feeds the Discover card.
// Records are folded live from the mesh store (dnsnet_zone); publishes go
// through dnsnet_publish with the wallet key (= the name's owner key).
#include "ui.h"
#include "../dnsnet.h"
#include "dns_wire.h"       // DNS_* type codes
#include "dns_state.h"      // DNS_BUDGET (the 8 KB per-name budget)

#include "../../vendor/sokol/sokol_app.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// wire dname (no compression in stored rdata) → dotted text
static void dname_str(const uint8_t *p, int len, char *out, size_t cap) {
    size_t o = 0;
    int i = 0;
    while (i < len && p[i] && o + 2 < cap) {
        int l = p[i++];
        if (l > len - i) break;
        if (o) out[o++] = '.';
        for (int k = 0; k < l && o + 1 < cap; k++) out[o++] = (char)p[i + k];
        i += l;
    }
    out[o] = 0;
}

// render rdata as the SAME text zone_build_rec parses — display and the edit
// modal share this, so a loaded value always round-trips
void ui_rdata_str(const zone_rec *r, char *out, size_t cap) {
    if (r->type == DNS_A && r->rdlen == 4) {
        snprintf(out, cap, "%u.%u.%u.%u", r->rdata[0], r->rdata[1], r->rdata[2], r->rdata[3]);
    } else if (r->type == DNS_AAAA && r->rdlen == 16) {
        char b[64]; inet_ntop(AF_INET6, r->rdata, b, sizeof b);
        snprintf(out, cap, "%s", b);
    } else if (r->type == DNS_CNAME || r->type == DNS_NS || r->type == DNS_PTR) {
        dname_str(r->rdata, r->rdlen, out, cap);
    } else if (r->type == DNS_MX && r->rdlen > 2) {
        char h[256];
        dname_str(r->rdata + 2, r->rdlen - 2, h, sizeof h);
        snprintf(out, cap, "%u %s", (r->rdata[0] << 8) | r->rdata[1], h);
    } else if (r->type == DNS_TXT) {          // skip the 1-byte len prefix
        int off = (r->rdlen > 0 && r->rdata[0] == r->rdlen - 1) ? 1 : 0;
        int n = r->rdlen - off; if (n > (int)cap - 1) n = (int)cap - 1;
        memcpy(out, r->rdata + off, (size_t)(n < 0 ? 0 : n)); out[n < 0 ? 0 : n] = 0;
    } else if (r->type == DNS_TLSA && r->rdlen >= 3) {
        size_t o = (size_t)snprintf(out, cap, "%u %u %u ",
                                    r->rdata[0], r->rdata[1], r->rdata[2]);
        for (int i = 3; i < r->rdlen && o + 2 < cap; i++)
            o += (size_t)snprintf(out + o, cap - o, "%02x", r->rdata[i]);
    } else if (r->type == DNS_SSHFP && r->rdlen >= 2) {
        size_t o = (size_t)snprintf(out, cap, "%u %u ", r->rdata[0], r->rdata[1]);
        for (int i = 2; i < r->rdlen && o + 2 < cap; i++)
            o += (size_t)snprintf(out + o, cap - o, "%02x", r->rdata[i]);
    } else {                                   // generic hex
        size_t o = 0;
        for (int i = 0; i < r->rdlen && o + 2 < cap; i++)
            o += (size_t)snprintf(out + o, cap - o, "%02x", r->rdata[i]);
        out[o] = 0;
    }
}

// pick a valid owned name for the per-name screens; -1 = none
int ui_dns_pick_name(void) {
    if (UI.dns_name_sel >= 0 && UI.dns_name_sel < M.nnames &&
        M.names[UI.dns_name_sel].st != NS_CLAIMING)
        return UI.dns_name_sel;
    for (int i = 0; i < M.nnames; i++)
        if (M.names[i].st != NS_CLAIMING) { UI.dns_name_sel = i; return i; }
    return -1;
}

static int is_sysmanaged(const zone_rec *r) {
    return r->type == DNS_TLSA && strncmp(r->label, "_443._tcp", 9) == 0;
}

void view_dns(struct nk_context *ctx, struct nk_rect area) {
    int ni = ui_dns_pick_name();
    if (ni < 0) {
        struct nk_rect r = nk_rect(area.x + 40, area.y + 60, area.w - 80, 62);
        dk_rect_dashed(ctx, r, 12, C_BORDER);
        dk_text_c(ctx, F_PH16, r, C_DIM, TR(S_DNS_EMPTY_NONAME));
        return;
    }
    const char *apex = M.names[ni].name;
    float top = ui_name_header(ctx, area, apex, TR(S_DNS_WHICH), TR(S_DNS_LINK_SSL), V_SSL);

    zone z;
    int nrec = M.demo ? 0 : dnsnet_zone(apex, &z);
    if (nrec < 0) nrec = 0;

    struct nk_rect view = nk_rect(area.x, top, area.w, area.y + area.h - top);
    dk_scroll_begin(ctx, &UI.sc_dns, view);
    float x = view.x + 16, xr = view.x + view.w - 16;
    float y = view.y + 14 - UI.sc_dns.scroll;

    // ── the records card ──────────────────────────────────────────────────────
    int nsys = 0;
    for (int i = 0; i < nrec; i++) if (is_sysmanaged(&z.recs[i])) nsys++;
    float head_h = 42, cols_h = 26, row_h = 34;
    float body_h = nrec > 0 ? nrec * row_h : 44;
    float foot_h = nsys ? 26 : 0;
    struct nk_rect card = nk_rect(x, y, xr - x, head_h + cols_h + body_h + foot_h);
    dk_card(ctx, card, 10, C_PANEL, C_BORDER);

    // header: title · count · + add record
    dk_text(ctx, F_PH16, x + 14, y + 9, C_TEXT, TR(S_DNS_RECORDS));
    char b[160];
    snprintf(b, sizeof b, TR(S_DNS_NRECORDS_FMT), nrec, nrec == 1 ? "" : "s");
    dk_text(ctx, F_SM10, x + 14 + dk_w(F_PH16, TR(S_DNS_RECORDS)) + 10, y + 14, C_GHOST, b);
    {
        float aw = dk_w(F_PH14, TR(S_DNS_ADD_RECORD)) + 26;
        struct nk_rect ab = nk_rect(xr - 12 - aw, y + 7, aw, 27);
        if (M.demo) {
            ui_btn_disabled(ctx, ab, F_PH14, TR(S_DNS_ADD_RECORD));
        } else if (dk_btn(ctx, ab, F_PH14, TR(S_DNS_ADD_RECORD), BTN_ACCENT)) {
            UI.dialog = DLG_DNS_REC;
            UI.dnsm_edit = 0;
            UI.dnsm_type_sel = 0;
            UI.dnsm_more = 0;
            UI.dnsm_host_len = 0; UI.dnsm_host[0] = 0;
            snprintf(UI.dnsm_ttl, sizeof UI.dnsm_ttl, "3600"); UI.dnsm_ttl_len = 4;
            UI.dnsm_val_len = 0; UI.dnsm_val[0] = 0;
        }
    }
    dk_hline(ctx, x + 1, xr - 1, y + head_h, C_BORDER);
    y += head_h;

    // column headers
    float cx_type = x + 14, cx_host = x + 96, cx_val = x + 196;
    float cx_ttl = xr - 96, cx_edit = xr - 46;
    dk_text_sp(ctx, F_SM9, cx_type, y + 8, C_GHOST, TR(S_COL_TYPE), 1);
    dk_text_sp(ctx, F_SM9, cx_host, y + 8, C_GHOST, TR(S_COL_HOST), 1);
    dk_text_sp(ctx, F_SM9, cx_val, y + 8, C_GHOST, TR(S_COL_VALUE), 1);
    dk_text_sp(ctx, F_SM9, cx_ttl - dk_w_sp(F_SM9, TR(S_COL_TTL), 1), y + 8, C_GHOST,
               TR(S_COL_TTL), 1);
    dk_hline(ctx, x + 1, xr - 1, y + cols_h, C_HAIR);
    y += cols_h;

    if (nrec == 0) {
        dk_text_c(ctx, F_PH12, nk_rect(x, y, xr - x, 44), C_GHOST,
                  M.demo ? TR(S_DNS_EMPTY_DEMO) : TR(S_DNS_EMPTY));
        y += 44;
    }
    for (int i = 0; i < nrec; i++) {
        zone_rec *r = &z.recs[i];
        int sys = is_sysmanaged(r);
        if (sys) dk_fill(ctx, nk_rect(x + 1, y, xr - x - 2, row_h), 0, HEXC(0x1C1E17));

        char tnb[16], rd[200];
        const char *tn = zone_type_name(r->type, tnb, sizeof tnb);
        ui_rdata_str(r, rd, sizeof rd);

        // type chip
        float tw = dk_w(F_SMB10, tn) + 14;
        struct nk_rect tc = nk_rect(cx_type, y + 8, tw, 18);
        nk_stroke_rect(dk_cv(ctx), tc, 4, 1.0f, C_BORDER);
        dk_text_c(ctx, F_SMB10, tc, sys ? C_FADE3 : C_GREEN, tn);

        dk_text(ctx, F_SM13, cx_host, y + 9, sys ? C_DIM : C_TEXT,
                r->label[0] ? r->label : "@");
        dk_clip_push(ctx, nk_rect(cx_val, y, cx_ttl - cx_val - 40, row_h));
        dk_text(ctx, F_SM11, cx_val, y + 10, sys ? C_FADE3 : C_DIM, rd);
        dk_clip_pop(ctx);
        snprintf(b, sizeof b, "%u", r->ttl);
        dk_text_r(ctx, F_SM11, cx_ttl, y + 10, C_GHOST, b);

        if (sys) {
            dk_text_r(ctx, F_PH16, cx_edit + 30, y + 6, C_GHOST, "\xF0\x9F\x94\x92");
        } else if (!M.demo) {
            struct nk_rect eb = nk_rect(cx_edit, y + 6, 40, 22);
            int hot = dk_hot(ctx, eb);
            dk_text_r(ctx, F_PH12, cx_edit + 30, y + 8, hot ? C_TEXT : C_DIM, TR(S_EDIT));
            if (hot) sapp_set_mouse_cursor(SAPP_MOUSECURSOR_POINTING_HAND);
            if (dk_click(ctx, eb)) {
                UI.dialog = DLG_DNS_REC;
                UI.dnsm_edit = 1;
                UI.dnsm_more = 1;                     // whatever type it is, show it
                snprintf(UI.dnsm_orig_label, sizeof UI.dnsm_orig_label, "%s", r->label);
                UI.dnsm_orig_type = r->type;
                snprintf(UI.dnsm_host, sizeof UI.dnsm_host, "%s",
                         r->label[0] ? r->label : "@");
                UI.dnsm_host_len = (int)strlen(UI.dnsm_host);
                snprintf(UI.dnsm_ttl, sizeof UI.dnsm_ttl, "%u", r->ttl);
                UI.dnsm_ttl_len = (int)strlen(UI.dnsm_ttl);
                snprintf(UI.dnsm_val, sizeof UI.dnsm_val, "%s", rd);
                UI.dnsm_val_len = (int)strlen(UI.dnsm_val);
                UI.dnsm_type_sel = ui_dnsm_type_from_code(r->type);
            }
        }
        if (i < nrec - 1) dk_hline(ctx, x + 1, xr - 1, y + row_h, C_HAIR);
        y += row_h;
    }
    if (nsys) {
        dk_fill(ctx, nk_rect(x + 1, y, xr - x - 2, foot_h - 1), 0, HEXC(0x1C1E17));
        dk_text(ctx, F_SM10, x + 14, y + 6, C_GHOST, TR(S_DNS_SYS_FOOT));
        y += foot_h;
    }
    y += 10;

    // ── zone storage: held bytes vs the 8 KB budget, and the clear valve ──────
    if (!M.demo) {
        int64_t used = dnsnet_zone_bytes(apex);
        if (used < 0) used = 0;
        float frac = (float)used / (float)DNS_BUDGET;
        if (frac > 1.0f) frac = 1.0f;
        snprintf(b, sizeof b, TR(S_DNS_USAGE_FMT), (long long)used, DNS_BUDGET);
        dk_text(ctx, F_SM10, x + 2, y, C_GHOST, b);
        // the clear button, right-aligned on the meter line (opens the confirm)
        float cwd = dk_w(F_SM10, TR(S_DNS_CLEAR_BTN)) + 8;
        struct nk_rect cb = nk_rect(xr - cwd, y - 2, cwd, 18);
        int chot = dk_hot(ctx, cb);
        dk_text_r(ctx, F_SM10, xr, y, used > 0 ? (chot ? C_RED : C_DIM) : C_FADE3,
                  TR(S_DNS_CLEAR_BTN));
        if (chot && used > 0) sapp_set_mouse_cursor(SAPP_MOUSECURSOR_POINTING_HAND);
        if (used > 0 && dk_click(ctx, cb)) UI.dialog = DLG_DNS_CLEAR;
        y += 16;
        // the bar: green while roomy, red past ~85 % (tombstone pressure)
        struct nk_rect track = nk_rect(x + 2, y, (xr - 2) - (x + 2), 5);
        dk_fill(ctx, track, 2, C_HAIR);
        if (frac > 0.003f) {
            struct nk_rect fill = nk_rect(track.x, track.y, track.w * frac, track.h);
            dk_fill(ctx, fill, 2, frac > 0.85f ? C_RED : C_GREEN);
        }
        y += 12;
        dk_text(ctx, F_SM9, x + 2, y, C_GHOST, TR(S_DNS_USAGE_NOTE));
        y += 18;
    }

    // engine-health banner: a dead/stuck dns plane must be impossible to miss
    if (!M.demo && !M.dns.running) {
        snprintf(b, sizeof b, TR(S_DNS_OFFLINE_FMT), M.dns.phase);
        dk_text(ctx, F_SM9, x + 2, y, C_RED, b);
        y += 16;
    } else if (!M.demo && M.dns.queued > 0) {
        snprintf(b, sizeof b, TR(S_DNS_QUEUED_FMT), M.dns.queued,
                 M.dns.queued == 1 ? "" : "s", M.dns.phase);
        dk_text(ctx, F_SM9, x + 2, y, C_RED, b);
        y += 16;
    }

    // publish feedback (the mesh's admit verdict)
    if (!M.demo && M.dns.last_pub[0]) {
        snprintf(b, sizeof b, TR(S_DNS_LASTPUB_FMT), M.dns.last_pub);
        dk_text(ctx, F_SM9, x + 2, y, M.dns.last_err[0] ? C_RED : C_GREEN, b);
        y += 16;
    }
    if (!M.demo) {
        dk_text(ctx, F_SM9, x + 2, y + 2, C_GHOST, TR(S_DNS_FOOTNOTE));
        y += 20;
    }
    y += 8;
    dk_scroll_end(ctx, &UI.sc_dns, view, (y + UI.sc_dns.scroll) - view.y, 0);
}
