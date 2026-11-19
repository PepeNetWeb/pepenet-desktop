// serve_store.c — see serve_store.h. A thin sqlite wrapper; its own file so the
// network cache can be dropped/capped without touching the fold db.
#include "serve_store.h"
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

struct ServeStore { sqlite3 *db; };

static const char *SCHEMA =
    "PRAGMA journal_mode=WAL;"
    "CREATE TABLE IF NOT EXISTS headers(height INTEGER PRIMARY KEY, hash BLOB, hdr BLOB);"
    "CREATE INDEX IF NOT EXISTS headers_hash ON headers(hash);"
    "CREATE TABLE IF NOT EXISTS blockwin(height INTEGER PRIMARY KEY, raw BLOB);"
    "CREATE TABLE IF NOT EXISTS blockstage(hash BLOB PRIMARY KEY, prev BLOB, raw BLOB, at INTEGER);"
    "CREATE INDEX IF NOT EXISTS blockstage_prev ON blockstage(prev);";

ServeStore *serve_store_open(const char *path) {
    sqlite3 *db;
    if (sqlite3_open(path, &db) != SQLITE_OK) return NULL;
    sqlite3_busy_timeout(db, 5000);
    if (sqlite3_exec(db, SCHEMA, NULL, NULL, NULL) != SQLITE_OK) { sqlite3_close(db); return NULL; }
    ServeStore *ss = malloc(sizeof *ss);
    if (!ss) { sqlite3_close(db); return NULL; }
    ss->db = db;
    return ss;
}
void serve_store_close(ServeStore *ss) {
    if (!ss) return;
    sqlite3_close(ss->db);
    free(ss);
}

void serve_store_put(ServeStore *ss, int64_t height, const uint8_t hash[32],
                     const uint8_t hdr[80], const uint8_t *raw, size_t rawlen,
                     int64_t tip) {
    if (!ss) return;
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(ss->db,
            "INSERT OR REPLACE INTO headers(height,hash,hdr) VALUES(?,?,?)", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, height);
        sqlite3_bind_blob(st, 2, hash, 32, SQLITE_STATIC);
        sqlite3_bind_blob(st, 3, hdr, 80, SQLITE_STATIC);
        sqlite3_step(st); sqlite3_finalize(st);
    }
    if (sqlite3_prepare_v2(ss->db,
            "INSERT OR REPLACE INTO blockwin(height,raw) VALUES(?,?)", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, height);
        sqlite3_bind_blob(st, 2, raw, (int)rawlen, SQLITE_STATIC);
        sqlite3_step(st); sqlite3_finalize(st);
    }
    // trim the window to the last SERVE_BLOCK_WINDOW behind tip
    if (sqlite3_prepare_v2(ss->db,
            "DELETE FROM blockwin WHERE height < ?", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, tip - SERVE_BLOCK_WINDOW);
        sqlite3_step(st); sqlite3_finalize(st);
    }
}

void serve_store_prune_above(ServeStore *ss, int64_t height) {
    if (!ss) return;
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(ss->db, "DELETE FROM headers WHERE height > ?", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, height); sqlite3_step(st); sqlite3_finalize(st);
    }
    if (sqlite3_prepare_v2(ss->db, "DELETE FROM blockwin WHERE height > ?", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, height); sqlite3_step(st); sqlite3_finalize(st);
    }
}

int64_t serve_store_tip(ServeStore *ss) {
    if (!ss) return -1;
    sqlite3_stmt *st; int64_t t = -1;
    if (sqlite3_prepare_v2(ss->db, "SELECT MAX(height) FROM headers", -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_type(st, 0) != SQLITE_NULL)
            t = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    return t;
}

int64_t serve_store_locate(ServeStore *ss, const uint8_t *locator, int nloc) {
    if (!ss) return -1;
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(ss->db, "SELECT height FROM headers WHERE hash=?", -1, &st, NULL) != SQLITE_OK)
        return -1;
    int64_t found = -1;
    for (int i = 0; i < nloc && found < 0; i++) {          // locator is newest→oldest
        sqlite3_reset(st);
        sqlite3_bind_blob(st, 1, locator + 32 * i, 32, SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_ROW) found = sqlite3_column_int64(st, 0);
    }
    sqlite3_finalize(st);
    return found;
}

size_t serve_store_headers_from(ServeStore *ss, int64_t after_height,
                                uint8_t *out, size_t outcap, int max, int *n) {
    *n = 0; size_t o = 0;
    if (!ss) return 0;
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(ss->db,
            "SELECT hdr FROM headers WHERE height > ? ORDER BY height ASC LIMIT ?", -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_int64(st, 1, after_height);
    sqlite3_bind_int(st, 2, max);
    while (sqlite3_step(st) == SQLITE_ROW && o + 80 <= outcap) {
        const void *h = sqlite3_column_blob(st, 0);
        if (h && sqlite3_column_bytes(st, 0) == 80) { memcpy(out + o, h, 80); o += 80; (*n)++; }
    }
    sqlite3_finalize(st);
    return o;
}

int serve_store_have(ServeStore *ss, const uint8_t hash[32]) {
    if (!ss) return 0;
    static const char *Q[2] = { "SELECT 1 FROM headers WHERE hash=?",
                                "SELECT 1 FROM blockstage WHERE hash=?" };
    for (int i = 0; i < 2; i++) {
        sqlite3_stmt *st;
        if (sqlite3_prepare_v2(ss->db, Q[i], -1, &st, NULL) != SQLITE_OK) continue;
        sqlite3_bind_blob(st, 1, hash, 32, SQLITE_STATIC);
        int got = sqlite3_step(st) == SQLITE_ROW;
        sqlite3_finalize(st);
        if (got) return 1;
    }
    return 0;
}

int serve_store_stage_put(ServeStore *ss, const uint8_t hash[32], const uint8_t prev[32],
                          const uint8_t *raw, size_t len, int64_t now) {
    if (!ss || !raw || !len) return 0;
    sqlite3_stmt *st; int fresh = 0;
    if (sqlite3_prepare_v2(ss->db,
            "INSERT OR IGNORE INTO blockstage(hash,prev,raw,at) VALUES(?,?,?,?)", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_blob(st, 1, hash, 32, SQLITE_STATIC);
        sqlite3_bind_blob(st, 2, prev, 32, SQLITE_STATIC);
        sqlite3_bind_blob(st, 3, raw, (int)len, SQLITE_STATIC);
        sqlite3_bind_int64(st, 4, now);
        sqlite3_step(st);
        sqlite3_finalize(st);
        fresh = sqlite3_changes(ss->db) > 0;
    }
    // junk bounds: age out abandoned rows, hard-cap to the freshest 32 — the
    // stage only ever needs the few blocks in flight on a 1-min chain
    if (sqlite3_prepare_v2(ss->db, "DELETE FROM blockstage WHERE at < ?", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, now - 3600);
        sqlite3_step(st); sqlite3_finalize(st);
    }
    if (sqlite3_prepare_v2(ss->db,
            "DELETE FROM blockstage WHERE hash NOT IN (SELECT hash FROM blockstage ORDER BY at DESC LIMIT 32)",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_step(st); sqlite3_finalize(st);
    }
    return fresh;
}

int serve_store_stage_next(ServeStore *ss, const uint8_t prev[32],
                           uint8_t hash_out[32], uint8_t **raw, size_t *len) {
    if (!ss) return 0;
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(ss->db,
            "SELECT hash, raw FROM blockstage WHERE prev=? LIMIT 1", -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_blob(st, 1, prev, 32, SQLITE_STATIC);
    int got = 0;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const void *h = sqlite3_column_blob(st, 0);
        const void *b = sqlite3_column_blob(st, 1);
        int n = sqlite3_column_bytes(st, 1);
        if (h && sqlite3_column_bytes(st, 0) == 32 && b && n > 0) {
            *raw = malloc((size_t)n);
            if (*raw) {
                memcpy(hash_out, h, 32);
                memcpy(*raw, b, (size_t)n); *len = (size_t)n; got = 1;
            }
        }
    }
    sqlite3_finalize(st);
    return got;
}

int serve_store_stage_pending(ServeStore *ss) {
    if (!ss) return 0;
    sqlite3_stmt *st; int n = 0;
    // rows whose hash we don't already hold as a header: blocks the mesh push
    // delivered that did NOT chain onto our tip. Known-hash rows (a staged
    // copy of a block the socket path folded meanwhile) don't count — they
    // just age out.
    if (sqlite3_prepare_v2(ss->db,
            "SELECT COUNT(*) FROM blockstage WHERE hash NOT IN (SELECT hash FROM headers)",
            -1, &st, NULL) != SQLITE_OK) return 0;
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

void serve_store_stage_del(ServeStore *ss, const uint8_t hash[32]) {
    if (!ss) return;
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(ss->db, "DELETE FROM blockstage WHERE hash=?", -1, &st, NULL) != SQLITE_OK) return;
    sqlite3_bind_blob(st, 1, hash, 32, SQLITE_STATIC);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

int serve_store_hash_at(ServeStore *ss, int64_t height, uint8_t out[32]) {
    if (!ss) return 0;
    sqlite3_stmt *st; int got = 0;
    if (sqlite3_prepare_v2(ss->db, "SELECT hash FROM headers WHERE height=?", -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_int64(st, 1, height);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const void *h = sqlite3_column_blob(st, 0);
        if (h && sqlite3_column_bytes(st, 0) == 32) { memcpy(out, h, 32); got = 1; }
    }
    sqlite3_finalize(st);
    return got;
}

int64_t serve_store_win_floor(ServeStore *ss) {
    if (!ss) return -1;
    sqlite3_stmt *st; int64_t h = -1;
    if (sqlite3_prepare_v2(ss->db, "SELECT MIN(height) FROM blockwin", -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_type(st, 0) != SQLITE_NULL)
            h = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    return h;
}

int serve_store_hashes_from(ServeStore *ss, int64_t after_height,
                            uint8_t (*out)[32], int max) {
    if (!ss || max <= 0) return 0;
    sqlite3_stmt *st; int n = 0;
    if (sqlite3_prepare_v2(ss->db,
            "SELECT hash FROM headers WHERE height > ? ORDER BY height ASC LIMIT ?", -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_int64(st, 1, after_height);
    sqlite3_bind_int(st, 2, max);
    while (n < max && sqlite3_step(st) == SQLITE_ROW) {
        const void *h = sqlite3_column_blob(st, 0);
        if (h && sqlite3_column_bytes(st, 0) == 32) memcpy(out[n++], h, 32);
    }
    sqlite3_finalize(st);
    return n;
}

int serve_store_block(ServeStore *ss, const uint8_t hash[32], uint8_t **raw, size_t *len) {
    if (!ss) return 0;
    sqlite3_stmt *st;
    // hash lives in headers; the raw block in blockwin at the same height
    if (sqlite3_prepare_v2(ss->db,
            "SELECT b.raw FROM headers h JOIN blockwin b ON b.height=h.height WHERE h.hash=?",
            -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_blob(st, 1, hash, 32, SQLITE_STATIC);
    int got = 0;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const void *b = sqlite3_column_blob(st, 0);
        int n = sqlite3_column_bytes(st, 0);
        if (b && n > 0) {
            *raw = malloc((size_t)n);
            if (*raw) { memcpy(*raw, b, (size_t)n); *len = (size_t)n; got = 1; }
        }
    }
    sqlite3_finalize(st);
    return got;
}
