// dbcheck.c — idx-03: read-only integrity + consistency check of a fold db
// (and optionally its serve-<coin>.db). Opens SQLITE_OPEN_READONLY, writes
// nothing, streams every table (O(1) memory beyond sqlite's page cache).
//
// ERRORS (exit 1) are states the indexer itself can never produce on a clean
// shutdown or a recovered crash; WARNINGS are benign-but-notable states (a
// crash gap the next sync start repairs, legacy rows without PoW bits).
#include "dbcheck.h"
#include "chain.h"
#include "sm.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

typedef struct { FILE *out; IdxCheckReport *r; } Ck;

static void ck_err(Ck *c, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); c->r->errors++;
    if (c->out) { fputs("ERROR ", c->out); vfprintf(c->out, fmt, ap); fputc('\n', c->out); }
    va_end(ap);
}
static void ck_warn(Ck *c, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); c->r->warnings++;
    if (c->out) { fputs("warn  ", c->out); vfprintf(c->out, fmt, ap); fputc('\n', c->out); }
    va_end(ap);
}
static void ck_ok(Ck *c, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    if (c->out) { fputs("ok    ", c->out); vfprintf(c->out, fmt, ap); fputc('\n', c->out); }
    va_end(ap);
}
static int64_t q1(sqlite3 *db, const char *sql, int64_t a, int *found) {
    sqlite3_stmt *st; int64_t v = 0; if (found) *found = 0;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    if (sqlite3_bind_parameter_count(st) >= 1) sqlite3_bind_int64(st, 1, a);
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_type(st, 0) != SQLITE_NULL) { v = sqlite3_column_int64(st, 0); if (found) *found = 1; }
    sqlite3_finalize(st); return v;
}
static int meta(sqlite3 *db, const char *k, char *out, int n) {
    sqlite3_stmt *st; int f = 0;
    if (sqlite3_prepare_v2(db, "SELECT v FROM meta WHERE k=?", -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(st, 1, k, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_text(st, 0)) { snprintf(out, (size_t)n, "%s", sqlite3_column_text(st, 0)); f = 1; }
    sqlite3_finalize(st); return f;
}
static int unhex32(const char *h, uint8_t o[32]) {
    if (!h || strlen(h) != 64) return 0;
    for (int i = 0; i < 32; i++) { unsigned v; if (sscanf(h + 2*i, "%2x", &v) != 1) return 0; o[i] = (uint8_t)v; }
    return 1;
}
static int integrity(Ck *c, sqlite3 *db, const char *label) {
    sqlite3_stmt *st; int bad = 0;
    if (sqlite3_prepare_v2(db, "PRAGMA integrity_check", -1, &st, NULL) != SQLITE_OK) { ck_err(c, "%s: integrity_check: %s", label, sqlite3_errmsg(db)); return 1; }
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *m = (const char *)sqlite3_column_text(st, 0);
        if (m && strcmp(m, "ok")) { if (bad++ < 10) ck_err(c, "%s: integrity_check: %s", label, m); }
    }
    sqlite3_finalize(st);
    if (!bad) ck_ok(c, "%s: sqlite integrity_check", label);
    return bad;
}
// count rows matching a bounded predicate; report as error if > 0
static void orphan(Ck *c, sqlite3 *db, const char *sql, int64_t a, const char *what) {
    int f; int64_t n = q1(db, sql, a, &f);
    if (n < 0) ck_err(c, "%s: query failed: %s", what, sqlite3_errmsg(db));
    else if (n > 0) { ck_err(c, "%s: %lld row(s)", what, (long long)n); c->r->orphans += n; }
}

int idx_db_check(const char *path, const char *serve_path, FILE *out, IdxCheckReport *r) {
    memset(r, 0, sizeof *r);
    Ck c = { out, r };
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        ck_err(&c, "cannot open %s read-only", path); sqlite3_close(db); return r->errors;
    }
    sqlite3_busy_timeout(db, 2000);
    if (integrity(&c, db, "fold db")) { sqlite3_close(db); return r->errors; }
    if (q1(db, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('meta','blocks','names','raw_blocks','epochs','utxos','commits','muts')", 0, NULL) != 8) {
        ck_err(&c, "fold db: schema incomplete (not an indexer db?)"); sqlite3_close(db); return r->errors;
    }
    // ── 1. sync cursor vs stored blocks ───────────────────────────────────────
    char hb[80], th[80];
    if (!meta(db, "height", hb, sizeof hb)) {
        int64_t nb = q1(db, "SELECT COUNT(*) FROM blocks", 0, NULL);
        if (nb > 0) ck_err(&c, "no sync cursor but %lld block row(s)", (long long)nb);
        else ck_ok(&c, "empty db (no sync cursor, no blocks)");
        r->height = -1;
    } else {
        int64_t h = strtoll(hb, NULL, 10); r->height = h;
        uint8_t tip[32]; int have_tip = meta(db, "tip", th, sizeof th) && unhex32(th, tip);
        if (!have_tip) ck_err(&c, "meta tip missing or malformed");
        int fb; int64_t hmin = q1(db, "SELECT MIN(height) FROM blocks", 0, &fb);
        int64_t hmax = q1(db, "SELECT MAX(height) FROM blocks", 0, NULL);
        sqlite3_stmt *st; int row = 0;
        sqlite3_prepare_v2(db, "SELECT hash FROM blocks WHERE height=?", -1, &st, NULL);
        sqlite3_bind_int64(st, 1, h);
        if (sqlite3_step(st) == SQLITE_ROW) {
            row = 1;
            if (sqlite3_column_bytes(st, 0) != 32) ck_err(&c, "blocks[%lld].hash is not 32 bytes", (long long)h);
            else if (have_tip && memcmp(sqlite3_column_blob(st, 0), tip, 32)) ck_err(&c, "tip hash disagrees with blocks[%lld].hash", (long long)h);
            else if (have_tip) ck_ok(&c, "tip %lld hash agrees with stored block", (long long)h);
        }
        sqlite3_finalize(st);
        if (!row) {
            // standing on the profile checkpoint (fresh or rolled to start): no row
            // at the cursor and none below it is legitimate; a gap under rows is not
            if (fb && hmin <= h) ck_err(&c, "no blocks row at tip %lld (rows exist from %lld)", (long long)h, (long long)hmin);
            else ck_ok(&c, "tip %lld is the checkpoint (no folded block yet)", (long long)h);
        }
        if (fb) {
            int64_t below = q1(db, "SELECT COUNT(*) FROM blocks WHERE height<=?", h, NULL);
            int64_t lo = hmin;
            if (below > 0 && below != (h < hmax ? h : hmax) - lo + 1)
                ck_err(&c, "blocks %lld..%lld are not contiguous (%lld rows)", (long long)lo, (long long)h, (long long)below);
            else if (below > 0) ck_ok(&c, "blocks %lld..%lld contiguous", (long long)lo, (long long)(h < hmax ? h : hmax));
            int64_t badh = q1(db, "SELECT COUNT(*) FROM blocks WHERE length(hash)<>32 OR hash IS NULL", 0, NULL);
            if (badh) ck_err(&c, "%lld blocks row(s) with a malformed hash", (long long)badh);
            int64_t nob = q1(db, "SELECT COUNT(*) FROM blocks WHERE bits=0", 0, NULL);
            if (nob) ck_warn(&c, "%lld legacy block row(s) without PoW bits (most-work reorgs refused below them)", (long long)nob);
            int64_t dup = q1(db, "SELECT COUNT(*) FROM (SELECT hash FROM blocks GROUP BY hash HAVING COUNT(*)>1)", 0, NULL);
            if (dup) ck_err(&c, "%lld block hash(es) stored at more than one height", (long long)dup);
        }
        // ── 2. orphaned rows (above the cursor or dangling) ───────────────────
        orphan(&c, db, "SELECT COUNT(*) FROM blocks WHERE height>?", h, "orphan blocks above tip");
        orphan(&c, db, "SELECT COUNT(*) FROM raw_blocks WHERE height>?", h, "orphan raw_blocks above tip");
        orphan(&c, db, "SELECT COUNT(*) FROM raw_blocks r WHERE NOT EXISTS (SELECT 1 FROM blocks b WHERE b.height=r.height)", 0, "raw_blocks without a blocks row");
        orphan(&c, db, "SELECT COUNT(*) FROM epochs WHERE start_height>?", h, "orphan epochs above tip");
        orphan(&c, db, "SELECT COUNT(*) FROM utxos WHERE height>?", h, "orphan utxos funded above tip");
        orphan(&c, db, "SELECT COUNT(*) FROM utxos WHERE spent_height>?", h, "utxo spends recorded above tip");
        orphan(&c, db, "SELECT COUNT(*) FROM utxos WHERE spent_height IS NOT NULL AND spent_height<height", 0, "utxos spent before they were funded");
        orphan(&c, db, "SELECT COUNT(*) FROM utxos u WHERE NOT EXISTS (SELECT 1 FROM watch w WHERE w.h160=u.h160)", 0, "utxos for an unwatched address");
        if (!r->orphans) ck_ok(&c, "no orphaned rows");
        // ── 3. projection sentinel ───────────────────────────────────────────
        char pb[32]; int64_t ph = meta(db, "proj_height", pb, sizeof pb) ? strtoll(pb, NULL, 10) : -1;
        r->proj_height = ph;
        int64_t nproj = q1(db, "SELECT (SELECT COUNT(*) FROM names)+(SELECT COUNT(*) FROM commits)+(SELECT COUNT(*) FROM muts)", 0, NULL);
        if (ph < 0 && nproj > 0) ck_err(&c, "projection rows present but no proj_height sentinel");
        else if (ph > h) ck_err(&c, "projection %lld is AHEAD of the sync cursor %lld", (long long)ph, (long long)h);
        else if (ph >= 0 && ph < h) ck_warn(&c, "crash gap: projection %lld behind cursor %lld (next sync/index start re-folds it)", (long long)ph, (long long)h);
        else if (ph < 0) ck_warn(&c, "no projection yet (cursor %lld; next start re-folds from the checkpoint)", (long long)h);
        else ck_ok(&c, "projection at cursor %lld", (long long)h);
        int64_t ref = ph >= 0 ? ph : h;
        orphan(&c, db, "SELECT COUNT(*) FROM commits WHERE commit_height>?", ref, "commits above the projection height");
        orphan(&c, db, "SELECT COUNT(*) FROM muts WHERE height>?", ref, "mutation stamps above the projection height");
        // ── 4. lease / market state ──────────────────────────────────────────
        // After folding block H every surviving row has MTP(H) < lease_expiry
        // (sm lapse rule), and a LISTED/OFFERED row has MTP(H) < offer_expiry.
        int64_t ts[11]; int nt = 0;
        { sqlite3_stmt *t; sqlite3_prepare_v2(db, "SELECT time FROM blocks WHERE height<? ORDER BY height DESC LIMIT 11", -1, &t, NULL);
          sqlite3_bind_int64(t, 1, ref);
          while (nt < 11 && sqlite3_step(t) == SQLITE_ROW) ts[nt++] = sqlite3_column_int64(t, 0);
          sqlite3_finalize(t); }
        for (int a = 0, b = nt - 1; a < b; a++, b--) { int64_t x = ts[a]; ts[a] = ts[b]; ts[b] = x; }
        int64_t mtp = nt ? sm_mtp(ts, nt) : 0;
        int full_mtp = nt == 11 && q1(db, "SELECT COUNT(*) FROM blocks WHERE height=?", ref, NULL) == 1;
        sqlite3_stmt *n;
        sqlite3_prepare_v2(db, "SELECT name,length(owner),st,lease_expiry,offer_expiry,length(seller),length(buyer),price,burn_leg,pay_leg,reserve_expiry,owner FROM names", -1, &n, NULL);
        int64_t bad = 0, lapsed = 0, epoch_mis = 0; int have_ep = meta(db, "epochs_from", pb, sizeof pb);
        sqlite3_stmt *ep = NULL;
        if (have_ep) sqlite3_prepare_v2(db, "SELECT owner FROM epochs WHERE name=? AND start_height<=? ORDER BY start_height DESC LIMIT 1", -1, &ep, NULL);
        while (sqlite3_step(n) == SQLITE_ROW) {
            const char *nm = (const char *)sqlite3_column_text(n, 0);
            int st = sqlite3_column_int(n, 2);
            int64_t le = sqlite3_column_int64(n, 3), oe = sqlite3_column_int64(n, 4);
            uint64_t price = (uint64_t)sqlite3_column_int64(n, 7), bl = (uint64_t)sqlite3_column_int64(n, 8), pl = (uint64_t)sqlite3_column_int64(n, 9);
            const char *why = NULL;
            if (sqlite3_column_int(n, 1) != 20 || sqlite3_column_int(n, 5) != 20 || sqlite3_column_int(n, 6) != 20) why = "malformed owner/seller/buyer blob";
            else if (st < SM_OWNED || st > SM_RESERVED) why = "state out of range";
            else if (st == SM_RESERVED && bl + pl > price) why = "reserved legs exceed price";
            if (why) { if (bad++ < 10) ck_err(&c, "name %s: %s", nm ? nm : "?", why); continue; }
            if (full_mtp && le <= mtp) { if (lapsed++ < 10) ck_err(&c, "name %s: lease_expiry %lld <= MTP %lld but still projected", nm, (long long)le, (long long)mtp); }
            if (full_mtp && (st == SM_LISTED || st == SM_OFFERED) && oe <= mtp) { if (lapsed++ < 10) ck_err(&c, "name %s: offer_expiry %lld <= MTP %lld but still listed", nm, (long long)oe, (long long)mtp); }
            if (ep && st == SM_OWNED) {   // the latest epoch row must name the current owner
                sqlite3_reset(ep); sqlite3_bind_text(ep, 1, nm, -1, SQLITE_STATIC); sqlite3_bind_int64(ep, 2, ref);
                if (sqlite3_step(ep) == SQLITE_ROW) {
                    if (sqlite3_column_type(ep, 0) == SQLITE_NULL || sqlite3_column_bytes(ep, 0) != 20 ||
                        memcmp(sqlite3_column_blob(ep, 0), sqlite3_column_blob(n, 11), 20))
                        { if (epoch_mis++ < 10) ck_warn(&c, "name %s: latest epoch owner differs from projected owner", nm); }
                }
            }
        }
        sqlite3_finalize(n); if (ep) sqlite3_finalize(ep);
        r->errors += 0; r->bad_names = bad + lapsed;
        if (!bad && !lapsed) ck_ok(&c, "name rows well-formed; leases/offers live at MTP %lld%s", (long long)mtp, full_mtp ? "" : " (MTP window incomplete: lapse check skipped)");
    }
    // ── 5. serve db: header chain vs the fold's blocks ──────────────────────
    if (serve_path) {
        sqlite3 *sv = NULL;
        if (sqlite3_open_v2(serve_path, &sv, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) ck_err(&c, "cannot open serve db %s", serve_path);
        else if (!integrity(&c, sv, "serve db")) {
            sqlite3_stmt *st; int64_t prevh = -2, nbad = 0, nmis = 0, nh = 0; uint8_t prev[32];
            sqlite3_prepare_v2(sv, "SELECT height,hash,hdr FROM headers ORDER BY height", -1, &st, NULL);
            sqlite3_stmt *bk; sqlite3_prepare_v2(db, "SELECT hash FROM blocks WHERE height=?", -1, &bk, NULL);
            while (sqlite3_step(st) == SQLITE_ROW) {
                int64_t hh = sqlite3_column_int64(st, 0); nh++;
                const uint8_t *hs = sqlite3_column_blob(st, 1), *hd = sqlite3_column_blob(st, 2);
                if (sqlite3_column_bytes(st, 1) != 32 || sqlite3_column_bytes(st, 2) != 80) { if (nbad++ < 10) ck_err(&c, "serve header %lld malformed", (long long)hh); prevh = -2; continue; }
                uint8_t d[32]; idx_sha256d(hd, 80, d);
                if (memcmp(d, hs, 32)) { if (nbad++ < 10) ck_err(&c, "serve header %lld: hash != sha256d(hdr)", (long long)hh); }
                if (prevh == hh - 1 && memcmp(hd + 4, prev, 32)) { if (nbad++ < 10) ck_err(&c, "serve header %lld does not link to %lld", (long long)hh, (long long)prevh); }
                if (r->height >= 0 && hh > r->height) { if (nbad++ < 10) ck_err(&c, "serve header %lld above the fold tip %lld", (long long)hh, (long long)r->height); }
                sqlite3_reset(bk); sqlite3_bind_int64(bk, 1, hh);
                if (sqlite3_step(bk) == SQLITE_ROW && (sqlite3_column_bytes(bk, 0) != 32 || memcmp(sqlite3_column_blob(bk, 0), hs, 32)))
                    { if (nmis++ < 10) ck_err(&c, "serve header %lld disagrees with fold blocks row", (long long)hh); }
                memcpy(prev, hs, 32); prevh = hh;
            }
            sqlite3_finalize(st); sqlite3_finalize(bk);
            if (!nbad && !nmis) ck_ok(&c, "serve headers (%lld) hash, link, and agree with fold blocks", (long long)nh);
        }
        sqlite3_close(sv);
    }
    sqlite3_close(db);
    if (out) fprintf(out, "check: %d error(s), %d warning(s)\n", r->errors, r->warnings);
    return r->errors;
}
