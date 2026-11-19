// view.c — read-only namespace ownership. Lifted from the vpost carrier
// (carrier/src/view.c); the two must stay behaviorally identical (§4.2). Only the
// dependency on carrier.h/vpost_core.h is gone — this compiles standalone against
// sqlite3.
//
// Epoch resolution: when the indexer DB carries the `epochs` projection
// (ownership history), owner_of(name @ H) is EXACT §4.2 — the recorded owner at
// that height, including lapses. For heights the history does not cover (a DB
// predating the projection, until a refold backfills it), it falls back to the
// current owner — conservative for impersonation (a non-owner never passes).
#include "pepenet/view.h"
#include "pepenet/crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

typedef struct { char name[SP_NAME_MAX + 1]; uint8_t owner[20]; } TestRow;

struct SpView {
    sqlite3 *db;            // chain mode
    int has_epochs;         // chain db carries the ownership-history projection
    TestRow *rows; int n;   // test mode
    uint32_t test_tip;
};

static int hex2bin(const char *h, uint8_t *out, int outlen) {
    for (int i = 0; i < outlen; i++) {
        unsigned b;
        if (sscanf(h + 2 * i, "%2x", &b) != 1) return 0;
        out[i] = (uint8_t)b;
    }
    return 1;
}

SpView *sp_view_open_chain(const char *path) {
    SpView *v = calloc(1, sizeof *v);
    if (sqlite3_open_v2(path, &v->db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        fprintf(stderr, "view: cannot open %s: %s\n", path, sqlite3_errmsg(v->db));
        sqlite3_close(v->db); free(v); return NULL;
    }
    sqlite3_busy_timeout(v->db, 5000);
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(v->db,
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='epochs'", -1, &st, NULL) == SQLITE_OK) {
        v->has_epochs = sqlite3_step(st) == SQLITE_ROW;
        sqlite3_finalize(st);
    }
    return v;
}

SpView *sp_view_open_test(const char *file, uint32_t tip) {
    FILE *f = fopen(file, "r");
    if (!f) { fprintf(stderr, "view: cannot open %s\n", file); return NULL; }
    SpView *v = calloc(1, sizeof *v);
    v->test_tip = tip;
    char name[64], hex[64];
    while (fscanf(f, "%63s %63s", name, hex) == 2) {
        size_t nlen = strlen(name);
        if (!sp_name_valid(name, nlen) || strlen(hex) != 40) continue;
        v->rows = realloc(v->rows, (size_t)(v->n + 1) * sizeof *v->rows);
        TestRow *r = &v->rows[v->n];
        memcpy(r->name, name, nlen); r->name[nlen] = '\0';
        if (hex2bin(hex, r->owner, 20)) v->n++;
    }
    fclose(f);
    return v;
}

void sp_view_close(SpView *v) {
    if (!v) return;
    if (v->db) sqlite3_close(v->db);
    free(v->rows); free(v);
}

uint32_t sp_view_tip(SpView *v) {
    if (!v->db) return v->test_tip;
    static const char *KEYS[2] = { "proj_height", "height" };
    for (int i = 0; i < 2; i++) {
        sqlite3_stmt *st; uint32_t tip = 0;
        char q[64]; snprintf(q, sizeof q, "SELECT v FROM meta WHERE k='%s'", KEYS[i]);
        if (sqlite3_prepare_v2(v->db, q, -1, &st, NULL) != SQLITE_OK) continue;
        if (sqlite3_step(st) == SQLITE_ROW)
            tip = (uint32_t)strtoul((const char *)sqlite3_column_text(st, 0), NULL, 10);
        sqlite3_finalize(st);
        if (tip) return tip;
    }
    return 0;
}

// §4.2 resolution from the indexer's epochs projection. Returns 1 owned · 0
// known-unowned at that height · -1 history does not cover (caller falls back).
static int owner_from_epochs(SpView *v, const uint8_t *name, int name_len,
                             uint32_t height, uint8_t owner[20]) {
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(v->db,
            "SELECT owner FROM epochs WHERE name=? AND start_height<=?"
            " ORDER BY start_height DESC LIMIT 1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text (st, 1, (const char *)name, name_len, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, (int64_t)height);
    int rc = -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        if (sqlite3_column_type(st, 0) != SQLITE_NULL && sqlite3_column_bytes(st, 0) == 20) {
            memcpy(owner, sqlite3_column_blob(st, 0), 20);
            rc = 1;
        } else rc = 0;                                  // lapse row: known-unowned
    } else {
        sqlite3_stmt *m;
        int64_t efrom = -1;
        if (sqlite3_prepare_v2(v->db, "SELECT v FROM meta WHERE k='epochs_from'", -1, &m, NULL) == SQLITE_OK) {
            if (sqlite3_step(m) == SQLITE_ROW)
                efrom = strtoll((const char *)sqlite3_column_text(m, 0), NULL, 10);
            sqlite3_finalize(m);
        }
        if (efrom >= 0 && efrom <= (int64_t)height) {
            sqlite3_stmt *f;
            if (sqlite3_prepare_v2(v->db, "SELECT MIN(start_height) FROM epochs WHERE name=?", -1, &f, NULL) == SQLITE_OK) {
                sqlite3_bind_text(f, 1, (const char *)name, name_len, SQLITE_STATIC);
                if (sqlite3_step(f) == SQLITE_ROW && sqlite3_column_type(f, 0) != SQLITE_NULL)
                    rc = (sqlite3_column_int64(f, 0) == efrom) ? -1 : 0;
                sqlite3_finalize(f);
            }
        }
    }
    sqlite3_finalize(st);
    return rc;
}

int sp_view_owner_of(SpView *v, const uint8_t *name, int name_len,
                     uint32_t height, uint8_t owner[20]) {
    // §3.1: consensus never mints an invalid name — treat as unowned.
    if (name_len < 1 || name_len > SP_NAME_MAX ||
        !sp_name_valid((const char *)name, (size_t)name_len)) return 0;
    if (!v->db) {
        for (int i = 0; i < v->n; i++)
            if ((int)strlen(v->rows[i].name) == name_len &&
                memcmp(v->rows[i].name, name, (size_t)name_len) == 0) {
                memcpy(owner, v->rows[i].owner, 20);
                return 1;
            }
        return 0;
    }
    if (v->has_epochs) {
        int rc = owner_from_epochs(v, name, name_len, height, owner);
        if (rc >= 0) return rc;                         // exact §4.2 answer
    }
    sqlite3_stmt *st; int found = 0;
    if (sqlite3_prepare_v2(v->db, "SELECT owner FROM names WHERE name=?", -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, (const char *)name, name_len, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_bytes(st, 0) == 20) {
        memcpy(owner, sqlite3_column_blob(st, 0), 20);
        found = 1;
    }
    sqlite3_finalize(st);
    return found;
}

int sp_view_owner_now(SpView *v, const char *name, uint8_t owner[20]) {
    return sp_view_owner_of(v, (const uint8_t *)name, (int)strlen(name), sp_view_tip(v), owner);
}

int sp_view_addr_owns_name(SpView *v, const uint8_t addr[20]) {
    if (!v->db) {
        for (int i = 0; i < v->n; i++)
            if (memcmp(v->rows[i].owner, addr, 20) == 0) return 1;
        return 0;
    }
    sqlite3_stmt *st; int found = 0;
    if (sqlite3_prepare_v2(v->db, "SELECT 1 FROM names WHERE owner=? LIMIT 1", -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_blob(st, 1, addr, 20, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) found = 1;
    sqlite3_finalize(st);
    return found;
}
