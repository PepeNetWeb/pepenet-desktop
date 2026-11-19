// attrib.c — §4 real-tx attribution. Byte-logic ported verbatim from
// protocol-sm/impls/c/src/attrib.c; only (a) the tx parser handles real varints &
// large in/out counts, (b) the sighash buffer is heap-sized to the tx, and (c) the
// curve gates call the libsecp shim (secp_on_curve / secp_ecdsa_verify) directly
// rather than the reference's injected oracle.
#include "attrib.h"
#include "sha256.h"
#include "ripemd160.h"
#include <string.h>
#include <stdlib.h>

// libsecp shim (secp256k1.h declares these; we avoid that name-colliding header).
int secp_on_curve(const uint8_t *pub, int plen);
int secp_ecdsa_verify(const uint8_t h[32], const uint8_t r[32], const uint8_t s[32], const uint8_t *pub, int plen);

static const uint8_t SECP_P[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F };
static const uint8_t SECP_N_HALF[32] = {
    0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0 };

static int be_cmp(const uint8_t *a, const uint8_t *b) { for (int i = 0; i < 32; i++) if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1; return 0; }
static void sha256(const uint8_t *d, int n, uint8_t o[32]) { SHA256_CTX c; sha256_init(&c); sha256_update(&c, d, (unsigned)n); sha256_final(&c, o); }
static void sha256d(const uint8_t *d, int n, uint8_t o[32]) { uint8_t t[32]; sha256(d, n, t); sha256(t, 32, o); }
static void hash160(const uint8_t *d, int n, uint8_t o[20]) { uint8_t t[32]; sha256(d, n, t); ripemd160(t, 32, o); }

// ── strict-DER + low-S; SIGHASH_ALL only (Rule 3/4) ───────────────────────────
static int der_parse(const uint8_t *p, int n, uint8_t r32[32], uint8_t s32[32]) {
    if (n < 9 || n > 73) return 0;
    if (p[n - 1] != 0x01) return 0;                       // SIGHASH_ALL only
    int dl = n - 1;
    if (p[0] != 0x30 || p[1] != dl - 2) return 0;
    if (p[2] != 0x02) return 0;
    int lenR = p[3];
    if (lenR == 0 || lenR > 33 || 4 + lenR + 2 > dl) return 0;
    const uint8_t *R = p + 4;
    if (R[0] & 0x80) return 0;
    if (lenR > 1 && R[0] == 0x00 && !(R[1] & 0x80)) return 0;
    if (p[4 + lenR] != 0x02) return 0;
    int lenS = p[5 + lenR];
    if (lenS == 0 || lenS > 33) return 0;
    if (6 + lenR + lenS != dl) return 0;
    const uint8_t *S = p + 6 + lenR;
    if (S[0] & 0x80) return 0;
    if (lenS > 1 && S[0] == 0x00 && !(S[1] & 0x80)) return 0;
    memset(r32, 0, 32); memset(s32, 0, 32);
    int rstart = lenR > 32 ? lenR - 32 : 0, rlen = lenR - rstart;
    memcpy(r32 + 32 - rlen, R + rstart, (size_t)rlen);
    int sstart = lenS > 32 ? lenS - 32 : 0, slen = lenS - sstart;
    memcpy(s32 + 32 - slen, S + sstart, (size_t)slen);
    if (be_cmp(s32, SECP_N_HALF) > 0) return 0;           // low-S
    return 1;
}
static int pub_enc_ok(const uint8_t *p, int n) {
    if (n == 33) return (p[0] == 0x02 || p[0] == 0x03) && be_cmp(p + 1, SECP_P) < 0;
    if (n == 65) return p[0] == 0x04 && be_cmp(p + 1, SECP_P) < 0 && be_cmp(p + 33, SECP_P) < 0;
    return 0;
}
static int take_push(const uint8_t *s, int n, int *pos, int *op, const uint8_t **data, int *dlen) {
    if (*pos >= n) return 0;
    int b = s[(*pos)++]; *op = b;
    if (b == 0x00) { *data = s + *pos; *dlen = 0; return 1; }
    if (b >= 0x01 && b <= 0x4b) { if (*pos + b > n) return 0; *data = s + *pos; *dlen = b; *pos += b; return 1; }
    if (b == 0x4c) { if (*pos + 1 > n) return 0; int L = s[*pos]; *pos += 1; if (L < 76 || L > 520 || *pos + L > n) return 0; *data = s + *pos; *dlen = L; *pos += L; return 1; }
    if (b == 0x4d) { if (*pos + 2 > n) return 0; int L = s[*pos] | (s[*pos + 1] << 8); *pos += 2; if (L < 256 || L > 520 || *pos + L > n) return 0; *data = s + *pos; *dlen = L; *pos += L; return 1; }
    return 0;
}
static int rs_template(const uint8_t *rs, int n, int *m_out, int *nkeys, uint8_t keys[][33]) {
    if (n < 1) return 0;
    int pos = 0, opm = rs[pos++];
    if (opm < 0x51 || opm > 0x60) return 0;
    int m = opm - 0x50, cnt = 0;
    while (pos < n && rs[pos] == 0x21) {
        if (pos + 1 + 33 > n) return 0;
        const uint8_t *k = rs + pos + 1;
        if (k[0] != 0x02 && k[0] != 0x03) return 0;
        if (be_cmp(k + 1, SECP_P) >= 0) return 0;
        if (cnt >= 15) return 0;
        memcpy(keys[cnt++], k, 33); pos += 34;
    }
    if (cnt == 0 || pos >= n) return 0;
    int opn = rs[pos++];
    if (opn < 0x51 || opn > 0x60) return 0;
    int nn = opn - 0x50;
    if (nn != cnt || m < 1 || m > nn || nn > 15) return 0;
    if (pos >= n || rs[pos++] != 0xAE) return 0;
    if (pos != n) return 0;
    *m_out = m; *nkeys = cnt; return 1;
}
// ── FindAndDelete (Bitcoin Core CScript::FindAndDelete semantics) ─────────────
static int next_op(const uint8_t *s, int n, int *pc) {
    if (*pc >= n) return 0;
    int op = s[(*pc)++], dl = 0;
    if (op < 0x4c) dl = op;
    else if (op == 0x4c) { if (*pc + 1 > n) { *pc = n; return 0; } dl = s[*pc]; *pc += 1; }
    else if (op == 0x4d) { if (*pc + 2 > n) { *pc = n; return 0; } dl = s[*pc] | (s[*pc + 1] << 8); *pc += 2; }
    else if (op == 0x4e) { if (*pc + 4 > n) { *pc = n; return 0; } dl = s[*pc] | (s[*pc+1] << 8) | (s[*pc+2] << 16) | ((int)s[*pc+3] << 24); *pc += 4; }
    if (*pc + dl > n) { *pc = n; return 0; }
    *pc += dl; return 1;
}
static void find_and_delete(uint8_t *s, int *slen, const uint8_t *pat, int patlen) {
    if (patlen == 0) return;
    uint8_t out[2048]; int ol = 0, n = *slen, pc = 0, pc2 = 0;
    for (;;) {
        memcpy(out + ol, s + pc2, (size_t)(pc - pc2)); ol += pc - pc2;
        while (n - pc >= patlen && memcmp(s + pc, pat, (size_t)patlen) == 0) pc += patlen;
        pc2 = pc;
        if (!next_op(s, n, &pc)) break;
    }
    memcpy(out + ol, s + pc2, (size_t)(n - pc2)); ol += n - pc2;
    memcpy(s, out, (size_t)ol); *slen = ol;
}
// ── byte emit ─────────────────────────────────────────────────────────────────
static void put(uint8_t *b, int *l, const uint8_t *d, int n) { memcpy(b + *l, d, (size_t)n); *l += n; }
static void put1(uint8_t *b, int *l, int v) { b[(*l)++] = (uint8_t)v; }
static void put_u32le(uint8_t *b, int *l, uint32_t v) { for (int i = 0; i < 4; i++) put1(b, l, (v >> (8*i)) & 0xff); }
static void put_u64le(uint8_t *b, int *l, uint64_t v) { for (int i = 0; i < 8; i++) put1(b, l, (v >> (8*i)) & 0xff); }
static void put_varint(uint8_t *b, int *l, uint64_t v) {
    if (v < 0xFD) put1(b, l, (int)v);
    else if (v <= 0xFFFF) { put1(b, l, 0xFD); put1(b, l, v & 0xff); put1(b, l, (v >> 8) & 0xff); }
    else if (v <= 0xFFFFFFFFULL) { put1(b, l, 0xFE); put_u32le(b, l, (uint32_t)v); }
    else { put1(b, l, 0xFF); put_u64le(b, l, v); }
}
static void emit_push(uint8_t *b, int *l, const uint8_t *d, int dlen) {
    if (dlen < 76) put1(b, l, dlen);
    else if (dlen <= 255) { put1(b, l, 0x4c); put1(b, l, dlen); }
    else { put1(b, l, 0x4d); put1(b, l, dlen & 0xff); put1(b, l, (dlen >> 8) & 0xff); }
    put(b, l, d, dlen);
}

// ── real-tx parse (full varint; pointers into raw) ───────────────────────────
#define A_MAX_IN  256
#define A_MAX_OUT 512
typedef struct { uint8_t outpoint[36]; const uint8_t *ss; int sslen; uint32_t seq; } AIn;
typedef struct { uint64_t value; const uint8_t *spk; int spklen; } AOut;
typedef struct { uint32_t version; int n_in; AIn in[A_MAX_IN]; int n_out; AOut out[A_MAX_OUT]; uint32_t locktime; } ATx;

static uint64_t rd_varint(const uint8_t *raw, int n, int *pos) {
    if (*pos >= n) return UINT64_MAX;
    uint8_t b = raw[(*pos)++];
    if (b < 0xFD) return b;
    if (b == 0xFD) { if (*pos + 2 > n) return UINT64_MAX; uint64_t v = raw[*pos] | (raw[*pos+1] << 8); *pos += 2; return v; }
    if (b == 0xFE) { if (*pos + 4 > n) return UINT64_MAX; uint64_t v = (uint32_t)(raw[*pos] | raw[*pos+1] << 8 | raw[*pos+2] << 16 | ((uint32_t)raw[*pos+3] << 24)); *pos += 4; return v; }
    if (*pos + 8 > n) return UINT64_MAX; uint64_t v = 0; for (int i = 0; i < 8; i++) v |= (uint64_t)raw[*pos+i] << (8*i); *pos += 8; return v;
}

static int tx_parse(const uint8_t *raw, int n, ATx *t) {
    int pos = 0;
    if (n < 10) return 0;
    if (raw[4] == 0x00 && raw[5] == 0x01) return 0;       // reject witness marker
    t->version = raw[0] | (raw[1] << 8) | (raw[2] << 16) | ((uint32_t)raw[3] << 24); pos = 4;
    uint64_t nin = rd_varint(raw, n, &pos);
    if (nin == 0 || nin > A_MAX_IN) return 0; t->n_in = (int)nin;
    for (int i = 0; i < t->n_in; i++) {
        if (pos + 36 > n) return 0; memcpy(t->in[i].outpoint, raw + pos, 36); pos += 36;
        uint64_t sl = rd_varint(raw, n, &pos); if (sl == UINT64_MAX || pos + (int)sl > n) return 0;
        t->in[i].ss = raw + pos; t->in[i].sslen = (int)sl; pos += (int)sl;
        if (pos + 4 > n) return 0; t->in[i].seq = raw[pos] | (raw[pos+1]<<8) | (raw[pos+2]<<16) | ((uint32_t)raw[pos+3]<<24); pos += 4;
    }
    uint64_t nout = rd_varint(raw, n, &pos);
    if (nout > A_MAX_OUT) return 0; t->n_out = (int)nout;
    for (int j = 0; j < t->n_out; j++) {
        if (pos + 8 > n) return 0; uint64_t v = 0; for (int k = 0; k < 8; k++) v |= (uint64_t)raw[pos+k] << (8*k); pos += 8; t->out[j].value = v;
        uint64_t sl = rd_varint(raw, n, &pos); if (sl == UINT64_MAX || pos + (int)sl > n) return 0;
        t->out[j].spk = raw + pos; t->out[j].spklen = (int)sl; pos += (int)sl;
    }
    if (pos + 4 > n) return 0;
    t->locktime = raw[pos] | (raw[pos+1]<<8) | (raw[pos+2]<<16) | ((uint32_t)raw[pos+3]<<24); pos += 4;
    return pos == n;
}

// legacy sighash for input k with the FindAndDelete-applied scriptCode (heap buf).
static int legacy_sighash(const ATx *t, int k, const uint8_t *scriptCode, int scLen, uint8_t out[32]) {
    size_t cap = 64;
    for (int i = 0; i < t->n_in; i++) cap += 36 + 9 + (i == k ? (size_t)scLen : 0) + 4;
    for (int j = 0; j < t->n_out; j++) cap += 8 + 9 + (size_t)t->out[j].spklen;
    cap += 64;
    uint8_t *b = malloc(cap); if (!b) return 0; int l = 0;
    put_u32le(b, &l, t->version);
    put_varint(b, &l, (uint64_t)t->n_in);
    for (int i = 0; i < t->n_in; i++) {
        put(b, &l, t->in[i].outpoint, 36);
        if (i == k) { put_varint(b, &l, (uint64_t)scLen); put(b, &l, scriptCode, scLen); }
        else put_varint(b, &l, 0);
        put_u32le(b, &l, t->in[i].seq);
    }
    put_varint(b, &l, (uint64_t)t->n_out);
    for (int j = 0; j < t->n_out; j++) {
        put_u64le(b, &l, t->out[j].value);
        put_varint(b, &l, (uint64_t)t->out[j].spklen);
        put(b, &l, t->out[j].spk, t->out[j].spklen);
    }
    put_u32le(b, &l, t->locktime);
    put_u32le(b, &l, 0x00000001);                         // 4-byte LE SIGHASH_ALL (§4)
    sha256d(b, l, out);
    free(b);
    return 1;
}

typedef struct { uint8_t r[32], s[32]; const uint8_t *data; int dlen; } ASig;

static void attribute(const ATx *t, int k, IdxAttr *res) {
    memset(res, 0, sizeof *res);
    if (k < 0 || k >= t->n_in) { res->status = IDX_ATTR_CLASSIFY; return; }
    const uint8_t *ss = t->in[k].ss; int n = t->in[k].sslen;

    int op[32]; const uint8_t *dat[32]; int dl[32], cnt = 0, pos = 0;
    while (pos < n) {
        if (cnt >= 32) { res->status = IDX_ATTR_CLASSIFY; return; }
        if (!take_push(ss, n, &pos, &op[cnt], &dat[cnt], &dl[cnt])) { res->status = IDX_ATTR_CLASSIFY; return; }
        cnt++;
    }

    int kind = 0; ASig sigs[15]; int nsig = 0;
    const uint8_t *pubkey = NULL; int publen = 0;
    uint8_t keys[15][33]; int nkeys = 0;
    uint8_t scriptCode[1024]; int scLen = 0;

    if (cnt == 2 && op[0] != 0x00 && op[1] != 0x00 &&
        der_parse(dat[0], dl[0], sigs[0].r, sigs[0].s) && pub_enc_ok(dat[1], dl[1])) {
        kind = 1; nsig = 1; sigs[0].data = dat[0]; sigs[0].dlen = dl[0];
        pubkey = dat[1]; publen = dl[1];
        hash160(pubkey, publen, res->identity); res->type = 0;
        scLen = 0; put1(scriptCode, &scLen, 0x76); put1(scriptCode, &scLen, 0xa9);
        put1(scriptCode, &scLen, 0x14); put(scriptCode, &scLen, res->identity, 20);
        put1(scriptCode, &scLen, 0x88); put1(scriptCode, &scLen, 0xac);
    } else if (cnt >= 3 && op[0] == 0x00 && dl[0] == 0) {
        int m, nk;
        if (rs_template(dat[cnt - 1], dl[cnt - 1], &m, &nk, keys) && (cnt - 2) == m) {
            int ok = 1;
            for (int i = 0; i < m; i++) {
                if (op[1 + i] == 0x00 || !der_parse(dat[1 + i], dl[1 + i], sigs[i].r, sigs[i].s)) { ok = 0; break; }
                sigs[i].data = dat[1 + i]; sigs[i].dlen = dl[1 + i];
            }
            if (ok) {
                kind = 2; nsig = m; nkeys = nk;
                hash160(dat[cnt - 1], dl[cnt - 1], res->identity); res->type = 1;
                scLen = dl[cnt - 1]; memcpy(scriptCode, dat[cnt - 1], (size_t)scLen);
            }
        }
    }
    if (kind == 0) { res->status = IDX_ATTR_CLASSIFY; return; }

    for (int i = 0; i < nsig; i++) {
        // every sig here passed der_parse, which admits only 9..73 bytes, so
        // the push pattern is at most 3 + 73 = 76 bytes. The guard is
        // unreachable; it restates that bound where GCC's range analysis can
        // see it (-Wstringop-overflow can't track it through der_parse).
        if (sigs[i].dlen < 9 || sigs[i].dlen > 73) continue;
        uint8_t pat[80]; int pl = 0; emit_push(pat, &pl, sigs[i].data, sigs[i].dlen);
        find_and_delete(scriptCode, &scLen, pat, pl);
    }
    if (!legacy_sighash(t, k, scriptCode, scLen, res->sighash)) { res->status = IDX_ATTR_CLASSIFY; return; }

    if (kind == 1) { if (!secp_on_curve(pubkey, publen)) { res->status = IDX_ATTR_ONCURVE; return; } }
    else { for (int i = 0; i < nkeys; i++) if (!secp_on_curve(keys[i], 33)) { res->status = IDX_ATTR_ONCURVE; return; } }

    int ok;
    if (kind == 1) ok = secp_ecdsa_verify(res->sighash, sigs[0].r, sigs[0].s, pubkey, publen);
    else {
        int si = 0, ki = 0;
        while (si < nsig && ki < nkeys) {
            if (secp_ecdsa_verify(res->sighash, sigs[si].r, sigs[si].s, keys[ki], 33)) { si++; ki++; }
            else ki++;
        }
        ok = (si == nsig);
    }
    res->status = ok ? IDX_ATTR_FOUND : IDX_ATTR_VERIFY;
}

int idx_attribute(const uint8_t *rawtx, size_t rawlen, int k, IdxAttr *out) {
    ATx t;
    if (!tx_parse(rawtx, (int)rawlen, &t)) { memset(out, 0, sizeof *out); out->status = IDX_ATTR_CLASSIFY; return out->status; }
    attribute(&t, k, out);
    return out->status;
}
