// state.c — anchor-ordered per-key LWW state (see state.h for the model).
//
// The §2.2 cert machinery is ported byte-for-byte from the retired vpost
// carrier (pepenet-social impls/c/src/vpost_core.c) so certs minted before the
// migration keep verifying; the op envelope is NEW (SP_STATE_VER leads the
// preimage, so a state-op signature can never be replayed as a vpost entry or
// a chain structure, and vice versa).
#include "pepenet/state.h"
#include "pepenet/crypto.h"
#include "pepenet/wire.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ── low-S (§2.4 admission rule, same constant the carrier pinned) ────────────
static const uint8_t N_HALF[32] = {
    0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0
};
static int be_cmp32(const uint8_t *a, const uint8_t *b) {
    for (int i = 0; i < 32; i++) if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    return 0;
}
static int low_s(const uint8_t s32[32]) { return be_cmp32(s32, N_HALF) <= 0; }

// ── §2.2 / §2.2b certs (wire-identical port) ─────────────────────────────────
static int multisig_parse(const uint8_t *rs, int len, int *m_out, int *n_out,
                          const uint8_t **pubs) {
    if (len < 3) return 0;
    if (rs[len - 1] != 0xAE) return 0;                        // OP_CHECKMULTISIG
    if (rs[0] < 0x51 || rs[0] > 0x60) return 0;               // OP_1..OP_16
    int m = rs[0] - 0x50;
    int nb = rs[len - 2];
    if (nb < 0x51 || nb > 0x60) return 0;
    int n = nb - 0x50;
    int off = 1, cnt = 0;
    while (off < len - 2) {
        if (rs[off] != 0x21) return 0;                        // push exactly 33
        if (off + 1 + 33 > len - 2) return 0;
        if (cnt >= n) return 0;
        pubs[cnt++] = rs + off + 1;
        off += 1 + 33;
    }
    if (cnt != n || m < 1 || m > n) return 0;
    *m_out = m; *n_out = n;
    return 1;
}

static int multisig_verify(const uint8_t id32[32], const uint8_t *sigs, int sig_count,
                           int m, const uint8_t **pubs, int n) {
    if (sig_count != m) return 0;                             // threshold is exact
    int si = 0, pj = 0;
    while (si < m && pj < n) {
        const uint8_t *sig = sigs + si * 64;
        int ok = low_s(sig + 32) && sp_ecdsa_verify(id32, sig, pubs[pj], 33);
        if (ok) { si++; pj++; }
        else    { pj++; }
        if (m - si > n - pj) return 0;
    }
    return si == m;
}

// ── bounds helpers (see the §"never narrow before validating" rule below) ────
//
// Every length and count in this file arrives as a wire uint64_t. Narrowing one
// to int BEFORE validating it is the bug class that produced the remote OOB
// read: (int)0x80000000 is negative, so `off + (int)v > len` passes, `off`
// walks backwards, and the next byte read lands outside the buffer. The rule
// enforced throughout sp_cert_parse()/sp_state_op_parse() is therefore:
//
//   * keep the invariant 0 <= off <= len at every point (sp_rvar guarantees it
//     on success, and NEED/TAKE below preserve it);
//   * express "are there n bytes left?" as a SUBTRACTION from the remaining
//     count, never as an addition to off — `len - off` cannot overflow given
//     the invariant, whereas `off + n` can;
//   * compare a wire length against the remaining bytes as uint64_t, and only
//     narrow to int AFTER it is known to fit.
//
#define REMAIN(off, len)   ((uint64_t)((len) - (off)))        // needs 0<=off<=len
#define NEED(n)            do { if (REMAIN(off, len) < (uint64_t)(n)) return 0; } while (0)
// v is an unvalidated wire length: bound it against the remaining bytes first.
#define TAKE(v)            do { if ((v) > REMAIN(off, len)) return 0; } while (0)

int sp_cert_parse(int cert_type, const uint8_t *c, int len, SpCert *out) {
    memset(out, 0, sizeof *out);
    if (len < 0) return 0;                                    // establishes off<=len
    int off = 0; uint64_t v;
    if (off >= len || c[off++] != SP_CERT_VER) return 0;
    if (!sp_rvar(c, len, &off, &v) || v < 1 || v > SP_NAME_MAX) return 0;
    TAKE(v);
    out->name = c + off; out->name_len = (int)v; off += (int)v;
    if (cert_type == SP_CERT_P2PKH) {
        NEED(33); out->owner_key = c + off; off += 33;
    } else if (cert_type == SP_CERT_P2SH) {
        if (!sp_rvar(c, len, &off, &v) || v < 3 || v > 520) return 0;
        TAKE(v);
        out->redeem = c + off; out->redeem_len = (int)v; off += (int)v;
    } else return 0;
    NEED(33); out->posting_key = c + off; off += 33;
    if (!sp_rvar(c, len, &off, &out->scope)) return 0;
    NEED(4); out->not_after = sp_rle32(c + off); off += 4;
    sp_sha256(c, (size_t)off, out->cert_id);                  // preimage ends here
    if (cert_type == SP_CERT_P2PKH) {
        NEED(64);
        out->sigs = c + off; out->n_sigs = 1; off += 64;
    } else {
        if (!sp_rvar(c, len, &off, &v) || v < 1 || v > 16) return 0;
        TAKE(v * 64);                                         // v<=16 => no overflow
        out->sigs = c + off; out->n_sigs = (int)v; off += (int)v * 64;
    }
    out->type = cert_type;
    out->wire_len = off;
    return 1;
}

int sp_cert_verify(const SpCert *ct, const uint8_t *name, int name_len,
                   const uint8_t posting_key[33], uint32_t height_anchor,
                   const uint8_t owner_h160[20]) {
    if (ct->name_len != name_len || memcmp(ct->name, name, (size_t)name_len) != 0) return 0;
    if (memcmp(ct->posting_key, posting_key, 33) != 0) return 0;
    if (!(height_anchor < ct->not_after)) return 0;
    if (ct->type == SP_CERT_P2PKH) {
        uint8_t h[20]; sp_hash160(ct->owner_key, 33, h);
        if (memcmp(h, owner_h160, 20) != 0) return 0;
        return low_s(ct->sigs + 32) &&
               sp_ecdsa_verify(ct->cert_id, ct->sigs, ct->owner_key, 33);
    }
    if (ct->type == SP_CERT_P2SH) {
        uint8_t h[20]; sp_hash160(ct->redeem, (size_t)ct->redeem_len, h);
        if (memcmp(h, owner_h160, 20) != 0) return 0;
        int m, n; const uint8_t *pubs[16];
        if (!multisig_parse(ct->redeem, ct->redeem_len, &m, &n, pubs)) return 0;
        return multisig_verify(ct->cert_id, ct->sigs, ct->n_sigs, m, pubs, n);
    }
    return 0;
}

int sp_cert_build_p2pkh(const uint8_t *name, int name_len,
                        const uint8_t owner_priv[32], const uint8_t posting_key[33],
                        uint64_t scope, uint32_t not_after,
                        uint8_t *out, int outmax) {
    if (name_len < 1 || name_len > SP_NAME_MAX) return -1;
    if (outmax < 1 + 3 + name_len + 33 + 33 + 10 + 4 + 64) return -1;
    uint8_t opub[33];
    if (!sp_pubkey(owner_priv, opub)) return -1;
    int n = 0;
    out[n++] = SP_CERT_VER;
    n += sp_wvar(out + n, (uint64_t)name_len); memcpy(out + n, name, (size_t)name_len); n += name_len;
    memcpy(out + n, opub, 33); n += 33;
    memcpy(out + n, posting_key, 33); n += 33;
    n += sp_wvar(out + n, scope);
    n += sp_wle32(out + n, not_after);
    uint8_t cert_id[32]; sp_sha256(out, (size_t)n, cert_id);
    uint8_t sig[64];
    if (!sp_ecdsa_sign(owner_priv, cert_id, sig)) return -1;  // libsecp → low-S
    memcpy(out + n, sig, 64); n += 64;
    return n;
}

// ── op codec ─────────────────────────────────────────────────────────────────
int sp_state_op_build(uint8_t op, const char *name,
                      const uint8_t *key, int key_len,
                      const uint8_t *payload, int payload_len,
                      uint32_t anchor, const uint8_t anchor_hash[32],
                      const uint8_t priv[32], const uint8_t pub33[33],
                      int cert_type, const uint8_t *cert, int cert_len,
                      uint8_t *out, int outmax) {
    size_t nlen = name ? strlen(name) : 0;
    if (!sp_name_valid(name, nlen)) return -1;
    if (op == SP_OP_PUT) { if (key_len < 1 || payload_len < 1) return -1; }
    else if (op == SP_OP_DEL) { if (key_len < 1 || payload_len != 0) return -1; }
    else if (op == SP_OP_CLEAR) { if (key_len != 0 || payload_len != 0) return -1; }
    else return -1;
    if (key_len > SP_STATE_KEY_MAX) return -1;
    if (cert_type != SP_CERT_NONE && (!cert || cert_len < 1)) return -1;
    int need = 1 + 1 + 3 + (int)nlen + 3 + key_len + 4 + 32 + 5 + payload_len
             + 1 + (cert_type != SP_CERT_NONE ? cert_len : 0) + 33 + 64;
    if (outmax < need || need > SP_STATE_OP_MAX) return -1;
    int n = 0;
    out[n++] = SP_STATE_VER;
    out[n++] = op;
    n += sp_wvar(out + n, (uint64_t)nlen); memcpy(out + n, name, nlen); n += (int)nlen;
    n += sp_wvar(out + n, (uint64_t)key_len);
    if (key_len) { memcpy(out + n, key, (size_t)key_len); n += key_len; }
    n += sp_wle32(out + n, anchor);
    memcpy(out + n, anchor_hash, 32); n += 32;
    n += sp_wvar(out + n, (uint64_t)payload_len);
    if (payload_len) { memcpy(out + n, payload, (size_t)payload_len); n += payload_len; }
    out[n++] = (uint8_t)cert_type;
    if (cert_type != SP_CERT_NONE) { memcpy(out + n, cert, (size_t)cert_len); n += cert_len; }
    memcpy(out + n, pub33, 33); n += 33;
    uint8_t id[32]; sp_sha256(out, (size_t)n, id);            // preimage ends here
    uint8_t sig[64];
    if (!sp_ecdsa_sign(priv, id, sig)) return -1;
    memcpy(out + n, sig, 64); n += 64;
    return n;
}

int sp_state_op_parse(const uint8_t *e, int len, SpStateOp *out) {
    memset(out, 0, sizeof *out);
    if (len < 2 || len > SP_STATE_OP_MAX || e[0] != SP_STATE_VER) return 0;
    out->op = e[1];
    if (out->op < SP_OP_PUT || out->op > SP_OP_CLEAR) return 0;
    int off = 2; uint64_t v;
    if (!sp_rvar(e, len, &off, &v) || v < 1 || v > SP_NAME_MAX) return 0;
    TAKE(v);
    out->name = e + off; out->name_len = (int)v; off += (int)v;
    if (!sp_rvar(e, len, &off, &v) || v > SP_STATE_KEY_MAX) return 0;
    TAKE(v);
    out->key = v ? e + off : NULL; out->key_len = (int)v; off += (int)v;
    NEED(4 + 32);
    out->anchor = sp_rle32(e + off); off += 4;
    out->anchor_hash = e + off; off += 32;
    if (!sp_rvar(e, len, &off, &v)) return 0;
    TAKE(v);                                                  // BEFORE any narrowing
    out->payload = v ? e + off : NULL; out->payload_len = (int)v; off += (int)v;
    if (off >= len) return 0;
    out->has_cert = e[off++];
    if (out->has_cert != SP_CERT_NONE) {
        if (!sp_cert_parse(out->has_cert, e + off, len - off, &out->cert)) return 0;
        off += out->cert.wire_len;                            // <= len - off by construction
    }
    if (REMAIN(off, len) != 33 + 64) return 0;                // exactly signer+sig left
    out->signer = e + off; off += 33;
    sp_sha256(e, (size_t)off, out->op_id);                    // preimage ends here
    out->sig = e + off; off += 64;
    // shape rules mirror the builder
    if (out->op == SP_OP_PUT   && (out->key_len < 1 || out->payload_len < 1)) return 0;
    if (out->op == SP_OP_DEL   && (out->key_len < 1 || out->payload_len != 0)) return 0;
    if (out->op == SP_OP_CLEAR && (out->key_len != 0 || out->payload_len != 0)) return 0;
    out->wire_len = off;
    return 1;
}

// ── store ────────────────────────────────────────────────────────────────────
struct SpState {
    sqlite3 *db;
    int      batch;                       // L9: inside sp_state_batch_begin/end
    void   (*on_change)(void *u, const char *name);   // L10: write notifier
    void    *on_change_u;
    sqlite3_stmt *q_dv;                   // L10: cached "PRAGMA data_version"
};

static const char *SCHEMA =
    "PRAGMA journal_mode=WAL;"
    "CREATE TABLE IF NOT EXISTS st_rows("
    "  name TEXT NOT NULL, key BLOB NOT NULL, op INTEGER, anchor INTEGER,"
    "  op_id BLOB, blob BLOB, PRIMARY KEY(name, key));"
    "CREATE TABLE IF NOT EXISTS st_names("
    "  name TEXT PRIMARY KEY, owner BLOB, floor INTEGER, sum_bytes INTEGER,"
    "  clear_id BLOB, clear_blob BLOB);";

SpState *sp_state_open(const char *path) {
    SpState *s = calloc(1, sizeof *s);
    if (sqlite3_open(path, &s->db) != SQLITE_OK) {
        fprintf(stderr, "state: cannot open %s: %s\n", path, sqlite3_errmsg(s->db));
        sqlite3_close(s->db); free(s); return NULL;
    }
    sqlite3_busy_timeout(s->db, 5000);
    char *errmsg = NULL;
    if (sqlite3_exec(s->db, SCHEMA, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "state: schema: %s\n", errmsg ? errmsg : "?");
        sqlite3_free(errmsg); sqlite3_close(s->db); free(s); return NULL;
    }
    return s;
}

void sp_state_close(SpState *s) {
    if (!s) return;
    if (s->on_change) s->on_change(s->on_change_u, "");      // "" = this handle is closing
    if (s->q_dv) sqlite3_finalize(s->q_dv);
    sqlite3_close(s->db); free(s);
}

// L10: the host may cache per-name derivations (dns_state's digest). Every
// committed write through THIS handle calls fn(u, name); NULL name = "assume
// everything changed" (a batch that failed to commit); "" = the handle is
// closing (forget it; names are never empty).
// Writes by OTHER connections/processes are visible via sp_state_data_version.
void sp_state_set_change_hook(SpState *s, void (*fn)(void *u, const char *name), void *u) {
    if (!s) return;
    s->on_change = fn; s->on_change_u = u;
}
static void notify_change(SpState *s, const char *name) {
    if (s->on_change) s->on_change(s->on_change_u, name);
}
// PRAGMA data_version: changes whenever ANOTHER connection commits to the file
// (never for this connection's own commits). -1 on error.
int64_t sp_state_data_version(SpState *s) {
    if (!s) return -1;
    if (!s->q_dv && sqlite3_prepare_v2(s->db, "PRAGMA data_version", -1, &s->q_dv, NULL) != SQLITE_OK) {
        s->q_dv = NULL; return -1;
    }
    int64_t v = -1;
    if (sqlite3_step(s->q_dv) == SQLITE_ROW) v = sqlite3_column_int64(s->q_dv, 0);
    sqlite3_reset(s->q_dv);
    return v;
}

// ── write plumbing ───────────────────────────────────────────────────────────
// Every writer below checks sqlite3_step(). Ignoring it silently drops a write
// that failed with SQLITE_BUSY / SQLITE_FULL / SQLITE_IOERR while the caller
// still reports success, which is how a rejected row used to be accounted as
// admitted. A step that does not reach SQLITE_DONE is a failed write, full stop.
static int step_done(sqlite3_stmt *st) {
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

// BEGIN IMMEDIATE (not deferred): take the write lock at the top of the
// critical section so two concurrent admits serialise here, instead of both
// reading the same sum_bytes and colliding — or deadlocking — at COMMIT.
//
// L9 (batch): between sp_state_batch_begin and _end the whole dump is ONE
// write transaction; each op's critical section becomes a SAVEPOINT inside it,
// so an op that fails still rolls back alone (same per-op atomicity as before)
// and the rest of the dump keeps going. If the outer transaction is gone
// (sqlite auto-rolled it back on an I/O error) the batch is abandoned and ops
// fall back to their own BEGIN IMMEDIATE, exactly as without a batch.
static int tx_begin(SpState *s) {
    if (s->batch && sqlite3_get_autocommit(s->db)) s->batch = 0;   // outer txn lost
    if (s->batch) return sqlite3_exec(s->db, "SAVEPOINT sp_op", NULL, NULL, NULL) == SQLITE_OK;
    return sqlite3_exec(s->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;
}
static int tx_commit(SpState *s) {
    if (s->batch) return sqlite3_exec(s->db, "RELEASE sp_op", NULL, NULL, NULL) == SQLITE_OK;
    return sqlite3_exec(s->db, "COMMIT",  NULL, NULL, NULL) == SQLITE_OK;
}
static void tx_abort(SpState *s) {
    if (s->batch) {
        sqlite3_exec(s->db, "ROLLBACK TO sp_op", NULL, NULL, NULL);
        sqlite3_exec(s->db, "RELEASE sp_op", NULL, NULL, NULL);
        return;
    }
    sqlite3_exec(s->db, "ROLLBACK", NULL, NULL, NULL);
}

int sp_state_batch_begin(SpState *s) {
    if (!s || s->batch || !sqlite3_get_autocommit(s->db)) return 0;
    if (sqlite3_exec(s->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) return 0;
    s->batch = 1;
    return 1;
}
int sp_state_batch_end(SpState *s) {
    if (!s) return 0;
    int was = s->batch; s->batch = 0;
    if (!was) return 1;                        // never opened / already abandoned
    if (sqlite3_get_autocommit(s->db)) { notify_change(s, NULL); return 0; }   // auto-rolled back
    if (sqlite3_exec(s->db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK) return 1;
    sqlite3_exec(s->db, "ROLLBACK", NULL, NULL, NULL);
    notify_change(s, NULL);                    // nothing in the batch landed
    return 0;
}

typedef struct {                                              // st_names row
    int      present;
    uint8_t  owner[20];
    uint32_t floor;
    int64_t  sum;
} NameMeta;

static int meta_get(SpState *s, const uint8_t *name, int nlen, NameMeta *m) {
    memset(m, 0, sizeof *m);
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(s->db, "SELECT owner,floor,sum_bytes FROM st_names WHERE name=?",
                           -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(st, 1, (const char *)name, nlen, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        m->present = 1;
        if (sqlite3_column_bytes(st, 0) == 20) memcpy(m->owner, sqlite3_column_blob(st, 0), 20);
        m->floor = (uint32_t)sqlite3_column_int64(st, 1);
        m->sum   = sqlite3_column_int64(st, 2);
    }
    sqlite3_finalize(st);
    return rc == SQLITE_ROW || rc == SQLITE_DONE;              // anything else is a db error
}

static int meta_put(SpState *s, const uint8_t *name, int nlen, const NameMeta *m,
                    const uint8_t *clear_id, const uint8_t *clear_blob, int clear_len) {
    sqlite3_stmt *st;
    if (clear_blob) {
        if (sqlite3_prepare_v2(s->db,
            "INSERT INTO st_names(name,owner,floor,sum_bytes,clear_id,clear_blob) VALUES(?,?,?,?,?,?)"
            " ON CONFLICT(name) DO UPDATE SET owner=excluded.owner,floor=excluded.floor,"
            " sum_bytes=excluded.sum_bytes,clear_id=excluded.clear_id,clear_blob=excluded.clear_blob",
            -1, &st, NULL) != SQLITE_OK) return 0;
        sqlite3_bind_blob(st, 5, clear_id, 32, SQLITE_STATIC);
        sqlite3_bind_blob(st, 6, clear_blob, clear_len, SQLITE_STATIC);
    } else {
        if (sqlite3_prepare_v2(s->db,
            "INSERT INTO st_names(name,owner,floor,sum_bytes) VALUES(?,?,?,?)"
            " ON CONFLICT(name) DO UPDATE SET owner=excluded.owner,floor=excluded.floor,"
            " sum_bytes=excluded.sum_bytes",
            -1, &st, NULL) != SQLITE_OK) return 0;
    }
    sqlite3_bind_text (st, 1, (const char *)name, nlen, SQLITE_STATIC);
    sqlite3_bind_blob (st, 2, m->owner, 20, SQLITE_STATIC);
    sqlite3_bind_int64(st, 3, (int64_t)m->floor);
    sqlite3_bind_int64(st, 4, m->sum);
    return step_done(st);
}

static int rows_wipe(SpState *s, const uint8_t *name, int nlen) {
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(s->db, "DELETE FROM st_rows WHERE name=?", -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(st, 1, (const char *)name, nlen, SQLITE_STATIC);
    return step_done(st);
}

static int fail(char *err, int errlen, const char *m) {
    if (err && errlen > 0) snprintf(err, (size_t)errlen, "%s", m);
    return 0;
}

int sp_state_admit(SpState *s, const SpChainOracle *o,
                   int64_t budget, uint64_t scope,
                   const uint8_t *e, int len, char *err, int errlen) {
    SpStateOp p;
    if (!sp_state_op_parse(e, len, &p)) return fail(err, errlen, "malformed op");
    if (!sp_name_valid((const char *)p.name, (size_t)p.name_len))
        return fail(err, errlen, "invalid name (§3.1)");
    char name[SP_NAME_MAX + 1];
    memcpy(name, p.name, (size_t)p.name_len); name[p.name_len] = '\0';

    // ownership: ops verify against the CURRENT owner (lease-gated by the
    // oracle) — a lapsed name admits nothing (the sweep drops its rows), a
    // transferred name starts an epoch.
    uint8_t owner[20];
    if (!o->owner_now(o->u, name, owner))
        return fail(err, errlen, "name unowned");

    // already-admitted op_id: skip ECDSA on replay (a mesh peer used to
    // re-dump a captured valid owner op and make us verify it every time)
    { sqlite3_stmt *st;
      int have = 0;
      if (sqlite3_prepare_v2(s->db,
              "SELECT 1 FROM st_rows WHERE name=? AND op_id=? LIMIT 1",
              -1, &st, NULL) == SQLITE_OK) {
          sqlite3_bind_text(st, 1, name, p.name_len, SQLITE_STATIC);
          sqlite3_bind_blob(st, 2, p.op_id, 32, SQLITE_STATIC);
          have = sqlite3_step(st) == SQLITE_ROW;
          sqlite3_finalize(st);
      }
      if (!have && sqlite3_prepare_v2(s->db,
              "SELECT 1 FROM st_names WHERE name=? AND clear_id=? LIMIT 1",
              -1, &st, NULL) == SQLITE_OK) {
          sqlite3_bind_text(st, 1, name, p.name_len, SQLITE_STATIC);
          sqlite3_bind_blob(st, 2, p.op_id, 32, SQLITE_STATIC);
          have = sqlite3_step(st) == SQLITE_ROW;
          sqlite3_finalize(st);
      }
      if (have) return -1;
    }

    // cheap authority before ECDSA: a hostile mesh peer used to dump 1024 ops
    // signed by *its* key for a live name and make us secp-verify each one
    // before "signer is not the owner". Cert path still needs the verify
    // (the signer is a delegate, not the owner key).
    if (p.has_cert == SP_CERT_NONE && !sp_key_is_owner(p.signer, 33, owner))
        return fail(err, errlen, "signer is not the owner");
    if (!low_s(p.sig + 32)) return fail(err, errlen, "high-S signature");
    if (!sp_ecdsa_verify(p.op_id, p.sig, p.signer, 33))
        return fail(err, errlen, "signature invalid");
    if (p.has_cert != SP_CERT_NONE) {
        if (!(p.cert.scope & scope)) return fail(err, errlen, "cert lacks scope");
        if (!sp_cert_verify(&p.cert, p.name, p.name_len, p.signer, p.anchor, owner))
            return fail(err, errlen, "delegation cert invalid");
    }

    // anchor: 1 ⇒ compare against the header we hold (mismatch = stale branch
    // or forgery ⇒ reject); 0 ⇒ the publisher is ahead of us ⇒ hold; -1 ⇒ the
    // height is below our horizon ⇒ admit on the signature alone.
    uint8_t hh[32];
    int ha = o->header_at(o->u, p.anchor, hh);
    if (ha == 0) { fail(err, errlen, "anchor ahead of tip"); return -2; }
    if (ha > 0 && memcmp(hh, p.anchor_hash, 32) != 0)
        return fail(err, errlen, "anchor hash not on our chain");

    // ── CRITICAL SECTION ─────────────────────────────────────────────────────
    // Everything from here down is one read-modify-write of st_names.sum_bytes:
    // read the held total, decide against the budget, write rows, write the new
    // total. sqlite serialises each STATEMENT, never a sequence — so without a
    // transaction two writers on the same name both read S and both store
    // S+own_delta, and one delta is lost permanently on disk. sum_bytes IS the
    // per-name budget accumulator, so an undercount silently disables the
    // budget. This applies to threads AND to the advertised multi-process
    // (indexerd over WAL) deployment, which is why the fix has to be a database
    // transaction and not a mutex.
    //
    // BEGIN IMMEDIATE acquires the write lock up front, so a second admit
    // blocks here (bounded by the busy timeout set in sp_state_open) rather
    // than doing its reads and then failing at COMMIT.
    //
    // Exit discipline: every path out of this block goes through commit_rv() or
    // dberr(). Logical rejections still COMMIT — an epoch pin performed above
    // is legitimate state advancement and must survive, exactly as it did
    // before this change. Only a genuine sqlite failure ROLLBACKs, and it fails
    // the admit instead of reporting a write that never landed as success.
    if (!tx_begin(s)) return fail(err, errlen, "cannot begin transaction");
    int wrote = 0;                              // L10: notify only real writes
    #define dberr()      do { tx_abort(s); return fail(err, errlen, "state write failed"); } while (0)
    #define commit_rv(r) do { if (!tx_commit(s)) dberr(); if (wrote) notify_change(s, name); return (r); } while (0)
    #define commit_fail(m) do { fail(err, errlen, m); if (!tx_commit(s)) dberr(); if (wrote) notify_change(s, name); return 0; } while (0)

    // epoch pin: owner changed ⇒ held rows are a prior epoch. Wipe, and raise
    // the floor to tip−REORG so the prior epoch cannot replay (fresh ops anchor
    // at tip−REORG, so the new owner is never blocked by this).
    NameMeta m;
    if (!meta_get(s, p.name, p.name_len, &m)) dberr();
    if (m.present && memcmp(m.owner, owner, 20) != 0) {
        wrote = 1;
        if (!rows_wipe(s, p.name, p.name_len)) dberr();
        uint32_t tip = o->tip(o->u);
        m.floor = tip > SP_STATE_REORG ? tip - SP_STATE_REORG : 0;
        m.sum = 0;
        memcpy(m.owner, owner, 20);
        if (!meta_put(s, p.name, p.name_len, &m, NULL, NULL, 0)) dberr();
        // a prior epoch's clear is void with its rows; drop it explicitly.
        sqlite3_stmt *st;
        if (sqlite3_prepare_v2(s->db, "UPDATE st_names SET clear_id=NULL,clear_blob=NULL WHERE name=?",
                               -1, &st, NULL) != SQLITE_OK) dberr();
        sqlite3_bind_text(st, 1, (const char *)p.name, p.name_len, SQLITE_STATIC);
        if (!step_done(st)) dberr();
    }
    if (!m.present) memcpy(m.owner, owner, 20);

    if (p.op == SP_OP_CLEAR) {
        sqlite3_stmt *st;
        if (sqlite3_prepare_v2(s->db, "SELECT clear_id FROM st_names WHERE name=?", -1, &st, NULL) != SQLITE_OK) dberr();
        sqlite3_bind_text(st, 1, (const char *)p.name, p.name_len, SQLITE_STATIC);
        int dup = sqlite3_step(st) == SQLITE_ROW && sqlite3_column_bytes(st, 0) == 32
               && memcmp(sqlite3_column_blob(st, 0), p.op_id, 32) == 0;
        sqlite3_finalize(st);
        if (dup) commit_rv(-1);
        if (m.present && m.floor > 0 && p.anchor <= m.floor)
            commit_fail("clear at or below floor");
        // void everything anchored below the new floor; survivors keep their bytes
        wrote = 1;                              // (committed even if the budget check below fails)
        if (sqlite3_prepare_v2(s->db, "DELETE FROM st_rows WHERE name=? AND anchor<?", -1, &st, NULL) != SQLITE_OK) dberr();
        sqlite3_bind_text (st, 1, (const char *)p.name, p.name_len, SQLITE_STATIC);
        sqlite3_bind_int64(st, 2, (int64_t)p.anchor);
        if (!step_done(st)) dberr();
        if (sqlite3_prepare_v2(s->db, "SELECT COALESCE(SUM(LENGTH(blob)),0) FROM st_rows WHERE name=?", -1, &st, NULL) != SQLITE_OK) dberr();
        sqlite3_bind_text(st, 1, (const char *)p.name, p.name_len, SQLITE_STATIC);
        int survivors_ok = sqlite3_step(st) == SQLITE_ROW;
        int64_t survivors = survivors_ok ? sqlite3_column_int64(st, 0) : 0;
        sqlite3_finalize(st);
        if (!survivors_ok) dberr();
        if (survivors + len > budget) commit_fail("per-name budget");
        m.floor = p.anchor;
        m.sum = survivors + len;
        wrote = 1;
        if (!meta_put(s, p.name, p.name_len, &m, p.op_id, e, len)) dberr();
        commit_rv(1);
    }

    // PUT / DEL — one row per key, strictly-higher anchor wins
    if (p.anchor < m.floor) commit_fail("anchor below floor");
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(s->db, "SELECT anchor,op_id,LENGTH(blob) FROM st_rows WHERE name=? AND key=?",
                           -1, &st, NULL) != SQLITE_OK) dberr();
    sqlite3_bind_text(st, 1, (const char *)p.name, p.name_len, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, p.key, p.key_len, SQLITE_STATIC);
    int64_t held_anchor = -1, held_len = 0; int dup = 0;
    int qrc = sqlite3_step(st);
    if (qrc == SQLITE_ROW) {
        held_anchor = sqlite3_column_int64(st, 0);
        dup = sqlite3_column_bytes(st, 1) == 32 && memcmp(sqlite3_column_blob(st, 1), p.op_id, 32) == 0;
        held_len = sqlite3_column_int64(st, 2);
    }
    sqlite3_finalize(st);
    if (qrc != SQLITE_ROW && qrc != SQLITE_DONE) dberr();
    if (dup) commit_rv(-1);
    if ((int64_t)p.anchor <= held_anchor)
        commit_fail("anchor does not raise the key (rate limit)");
    if (m.sum - held_len + len > budget) commit_fail("per-name budget");

    wrote = 1;
    if (sqlite3_prepare_v2(s->db,
        "INSERT OR REPLACE INTO st_rows(name,key,op,anchor,op_id,blob) VALUES(?,?,?,?,?,?)",
        -1, &st, NULL) != SQLITE_OK) dberr();
    sqlite3_bind_text (st, 1, (const char *)p.name, p.name_len, SQLITE_STATIC);
    sqlite3_bind_blob (st, 2, p.key, p.key_len, SQLITE_STATIC);
    sqlite3_bind_int  (st, 3, p.op);
    sqlite3_bind_int64(st, 4, (int64_t)p.anchor);
    sqlite3_bind_blob (st, 5, p.op_id, 32, SQLITE_STATIC);
    sqlite3_bind_blob (st, 6, e, len, SQLITE_STATIC);
    if (!step_done(st)) dberr();
    m.sum = m.sum - held_len + len;
    if (!meta_put(s, p.name, p.name_len, &m, NULL, NULL, 0)) dberr();
    commit_rv(1);
    #undef dberr
    #undef commit_rv
    #undef commit_fail
}

// ── reads ────────────────────────────────────────────────────────────────────
int sp_state_get(SpState *s, const char *name, const uint8_t *key, int key_len,
                 uint8_t **blob, int *blen) {
    sqlite3_stmt *st; int found = 0;
    sqlite3_prepare_v2(s->db, "SELECT blob FROM st_rows WHERE name=? AND key=?", -1, &st, NULL);
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, key, key_len, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) {
        int n = sqlite3_column_bytes(st, 0);
        if (blob) { *blob = malloc((size_t)n); memcpy(*blob, sqlite3_column_blob(st, 0), (size_t)n); }
        if (blen) *blen = n;
        found = 1;
    }
    sqlite3_finalize(st);
    return found;
}

int sp_state_iter(SpState *s, const char *name,
                  int (*cb)(void *u, const uint8_t *key, int key_len, int op,
                            uint32_t anchor, const uint8_t *blob, int blen),
                  void *u) {
    sqlite3_stmt *st; int n = 0;
    sqlite3_prepare_v2(s->db,
        "SELECT key,op,anchor,blob FROM st_rows WHERE name=? ORDER BY key", -1, &st, NULL);
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    while (sqlite3_step(st) == SQLITE_ROW) {
        if (!cb(u, sqlite3_column_blob(st, 0), sqlite3_column_bytes(st, 0),
                sqlite3_column_int(st, 1), (uint32_t)sqlite3_column_int64(st, 2),
                sqlite3_column_blob(st, 3), sqlite3_column_bytes(st, 3))) break;
        n++;
    }
    sqlite3_finalize(st);
    return n;
}

int64_t sp_state_sum(SpState *s, const char *name) {
    sqlite3_stmt *st; int64_t sum = 0;
    sqlite3_prepare_v2(s->db, "SELECT sum_bytes FROM st_names WHERE name=?", -1, &st, NULL);
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) sum = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return sum;
}

uint32_t sp_state_floor(SpState *s, const char *name) {
    sqlite3_stmt *st; uint32_t f = 0;
    sqlite3_prepare_v2(s->db, "SELECT floor FROM st_names WHERE name=?", -1, &st, NULL);
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) f = (uint32_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return f;
}

int sp_state_clear_get(SpState *s, const char *name, uint8_t **blob, int *blen) {
    sqlite3_stmt *st; int found = 0;
    sqlite3_prepare_v2(s->db, "SELECT clear_blob FROM st_names WHERE name=? AND clear_blob IS NOT NULL",
                       -1, &st, NULL);
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) {
        int n = sqlite3_column_bytes(st, 0);
        if (blob) { *blob = malloc((size_t)n); memcpy(*blob, sqlite3_column_blob(st, 0), (size_t)n); }
        if (blen) *blen = n;
        found = 1;
    }
    sqlite3_finalize(st);
    return found;
}

int sp_state_names(SpState *s, int (*cb)(void *u, const char *name), void *u) {
    sqlite3_stmt *st; int n = 0;
    sqlite3_prepare_v2(s->db, "SELECT name FROM st_names ORDER BY name", -1, &st, NULL);
    while (sqlite3_step(st) == SQLITE_ROW) {
        if (!cb(u, (const char *)sqlite3_column_text(st, 0))) break;
        n++;
    }
    sqlite3_finalize(st);
    return n;
}

// Paged name walk (read-only; no schema change): names strictly after `after`
// ("" or NULL = from the start), in name order, at most `limit`. Lets the
// overlay page its anti-entropy and the expiry sweep resume where it stopped
// instead of rescanning the same first rows.
int sp_state_names_after(SpState *s, const char *after, int limit,
                         int (*cb)(void *u, const char *name), void *u) {
    sqlite3_stmt *st; int n = 0;
    if (limit <= 0) return 0;
    if (sqlite3_prepare_v2(s->db, "SELECT name FROM st_names WHERE name>? ORDER BY name LIMIT ?",
                           -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(st, 1, after ? after : "", -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, limit);
    while (sqlite3_step(st) == SQLITE_ROW) {
        n++;
        if (!cb(u, (const char *)sqlite3_column_text(st, 0))) break;
    }
    sqlite3_finalize(st);
    return n;
}

// The owner the held rows were admitted under (st_names.owner, pinned by the
// epoch logic in sp_state_admit). 1 = known (owner filled), 0 = no row.
int sp_state_owner(SpState *s, const char *name, uint8_t owner[20]) {
    sqlite3_stmt *st; int found = 0;
    if (sqlite3_prepare_v2(s->db, "SELECT owner FROM st_names WHERE name=?", -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_bytes(st, 0) == 20) {
        memcpy(owner, sqlite3_column_blob(st, 0), 20);
        found = 1;
    }
    sqlite3_finalize(st);
    return found;
}

void sp_state_drop_name(SpState *s, const char *name) {
    static const char *Q[2] = { "DELETE FROM st_rows WHERE name=?",
                                "DELETE FROM st_names WHERE name=?" };
    // Both deletes are one logical drop: rows without their st_names row (or
    // the reverse) is a half-dropped name. Transaction + checked steps.
    if (!tx_begin(s)) return;
    for (int i = 0; i < 2; i++) {
        sqlite3_stmt *st;
        if (sqlite3_prepare_v2(s->db, Q[i], -1, &st, NULL) != SQLITE_OK) { tx_abort(s); return; }
        sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
        if (!step_done(st)) { tx_abort(s); return; }
    }
    if (!tx_commit(s)) { tx_abort(s); return; }
    notify_change(s, name);
}
