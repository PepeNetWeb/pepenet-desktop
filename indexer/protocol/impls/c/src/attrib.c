// §4 Stateless Identity & Attribution — the byte-logic shell (see attrib.h).
#include "attrib.h"
#include "prng.h"
#include "sha256.h"
#include "ripemd160.h"
#include "secp256k1.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// ── secp256k1 constants (big-endian) ──────────────────────────────────────────
static const uint8_t SECP_P[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F };
static const uint8_t SECP_N_HALF[32] = {
    0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0 };

static int be_cmp(const uint8_t *a, const uint8_t *b) {           // 32-byte BE compare
    for (int i = 0; i < 32; i++) { if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1; }
    return 0;
}

// ── hashing helpers ───────────────────────────────────────────────────────────
static void sha256(const uint8_t *d, int n, uint8_t out[32]) {
    SHA256_CTX c; sha256_init(&c); sha256_update(&c, d, (unsigned)n); sha256_final(&c, out);
}
static void sha256d(const uint8_t *d, int n, uint8_t out[32]) {
    uint8_t t[32]; sha256(d, n, t); sha256(t, 32, out);
}
static void hash160(const uint8_t *d, int n, uint8_t out[20]) {
    uint8_t t[32]; sha256(d, n, t); ripemd160(t, 32, out);
}

// ── injected curve oracle (pinned pseudo-functions; replace with secp256k1 in B) ──
// on-curve iff SHA256(0x4F ‖ pubkey)[0] != 0  (≈255/256 true)
static int inj_on_curve(const uint8_t *pub, int plen) {
    uint8_t buf[1 + 65], h[32]; buf[0] = 0x4F; memcpy(buf + 1, pub, (size_t)plen);
    sha256(buf, 1 + plen, h); return h[0] != 0x00;
}
// verify iff SHA256(0x56 ‖ hash32 ‖ r32 ‖ s32 ‖ pubkey)[0] >= 0x20  (≈87.5% true)
static int inj_verify(const uint8_t hash32[32], const uint8_t r32[32], const uint8_t s32[32],
                      const uint8_t *pub, int plen) {
    uint8_t buf[1 + 32 + 32 + 32 + 65], h[32]; int n = 0;
    buf[n++] = 0x56;
    memcpy(buf + n, hash32, 32); n += 32;
    memcpy(buf + n, r32, 32);    n += 32;
    memcpy(buf + n, s32, 32);    n += 32;
    memcpy(buf + n, pub, (size_t)plen); n += plen;
    sha256(buf, n, h); return h[0] >= 0x20;
}

// ── strict-DER + low-S (real) ─────────────────────────────────────────────────
// p = sig push data = DER ‖ sighash-type(1). Fills r32/s32 (BE, right-aligned).
static int der_parse(const uint8_t *p, int n, uint8_t r32[32], uint8_t s32[32]) {
    if (n < 9 || n > 73) return 0;
    if (p[n - 1] != 0x01) return 0;                  // SIGHASH_ALL only (Rule 3)
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
    if (6 + lenR + lenS != dl) return 0;             // exact length, no trailing
    const uint8_t *S = p + 6 + lenR;
    if (S[0] & 0x80) return 0;
    if (lenS > 1 && S[0] == 0x00 && !(S[1] & 0x80)) return 0;
    memset(r32, 0, 32); memset(s32, 0, 32);
    int rstart = lenR > 32 ? lenR - 32 : 0, rlen = lenR - rstart;
    memcpy(r32 + 32 - rlen, R + rstart, (size_t)rlen);
    int sstart = lenS > 32 ? lenS - 32 : 0, slen = lenS - sstart;
    memcpy(s32 + 32 - slen, S + sstart, (size_t)slen);
    if (be_cmp(s32, SECP_N_HALF) > 0) return 0;      // low-S
    return 1;
}

// ── canonical pubkey ENCODING (real, sans on-curve) ───────────────────────────
static int pub_enc_ok(const uint8_t *p, int n) {
    if (n == 33) return (p[0] == 0x02 || p[0] == 0x03) && be_cmp(p + 1, SECP_P) < 0;
    if (n == 65) return p[0] == 0x04 && be_cmp(p + 1, SECP_P) < 0 && be_cmp(p + 33, SECP_P) < 0;
    return 0;
}

// ── minimal-push scriptSig iterator (real) ────────────────────────────────────
// Returns 1 and fills op/data/dlen, advancing *pos; 0 on non-minimal/non-push/end.
static int take_push(const uint8_t *s, int n, int *pos, int *op, const uint8_t **data, int *dlen) {
    if (*pos >= n) return 0;
    int b = s[(*pos)++]; *op = b;
    if (b == 0x00) { *data = s + *pos; *dlen = 0; return 1; }            // OP_0
    if (b >= 0x01 && b <= 0x4b) {
        if (*pos + b > n) return 0; *data = s + *pos; *dlen = b; *pos += b; return 1;
    }
    if (b == 0x4c) {                                                     // PUSHDATA1
        if (*pos + 1 > n) return 0; int L = s[*pos]; *pos += 1;
        if (L < 76 || L > 520 || *pos + L > n) return 0;                 // minimal: 76..520
        *data = s + *pos; *dlen = L; *pos += L; return 1;
    }
    if (b == 0x4d) {                                                     // PUSHDATA2
        if (*pos + 2 > n) return 0; int L = s[*pos] | (s[*pos + 1] << 8); *pos += 2;
        if (L < 256 || L > 520 || *pos + L > n) return 0;                // minimal: 256..520
        *data = s + *pos; *dlen = L; *pos += L; return 1;
    }
    return 0;                                                           // opcode, not a data push
}

// ── P2SH multisig redeemScript template (real) ────────────────────────────────
static int rs_template(const uint8_t *rs, int n, int *m_out, int *nkeys, uint8_t keys[][33]) {
    if (n < 1) return 0;
    int pos = 0, opm = rs[pos++];
    if (opm < 0x51 || opm > 0x60) return 0;
    int m = opm - 0x50, cnt = 0;
    while (pos < n && rs[pos] == 0x21) {                                // 33-byte compressed key
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
    if (pos >= n || rs[pos++] != 0xAE) return 0;                        // OP_CHECKMULTISIG
    if (pos != n) return 0;                                            // no trailing
    *m_out = m; *nkeys = cnt; return 1;
}

// ── FindAndDelete (real; Bitcoin Core CScript::FindAndDelete semantics) ───────
static int next_op(const uint8_t *s, int n, int *pc) {
    if (*pc >= n) return 0;
    int op = s[(*pc)++], dl = 0;
    if (op < 0x4c) dl = op;
    else if (op == 0x4c) { if (*pc + 1 > n) { *pc = n; return 0; } dl = s[*pc]; *pc += 1; }
    else if (op == 0x4d) { if (*pc + 2 > n) { *pc = n; return 0; } dl = s[*pc] | (s[*pc + 1] << 8); *pc += 2; }
    else if (op == 0x4e) { if (*pc + 4 > n) { *pc = n; return 0; }
        dl = s[*pc] | (s[*pc+1] << 8) | (s[*pc+2] << 16) | ((int)s[*pc+3] << 24); *pc += 4; }
    if (*pc + dl > n) { *pc = n; return 0; }
    *pc += dl; return 1;
}
static void find_and_delete(uint8_t *s, int *slen, const uint8_t *pat, int patlen) {
    if (patlen == 0) return;
    uint8_t out[8192]; int ol = 0, n = *slen, pc = 0, pc2 = 0;
    for (;;) {
        memcpy(out + ol, s + pc2, (size_t)(pc - pc2)); ol += pc - pc2;
        while (n - pc >= patlen && memcmp(s + pc, pat, (size_t)patlen) == 0) pc += patlen;
        pc2 = pc;
        if (!next_op(s, n, &pc)) break;
    }
    memcpy(out + ol, s + pc2, (size_t)(n - pc2)); ol += n - pc2;
    memcpy(s, out, (size_t)ol); *slen = ol;
}

// ── byte emit helpers ─────────────────────────────────────────────────────────
static void put(uint8_t *b, int *l, const uint8_t *d, int n) { memcpy(b + *l, d, (size_t)n); *l += n; }
static void put1(uint8_t *b, int *l, int v) { b[(*l)++] = (uint8_t)v; }
static void put_u32le(uint8_t *b, int *l, uint32_t v) { for (int i = 0; i < 4; i++) put1(b, l, (v >> (8*i)) & 0xff); }
static void put_u64le(uint8_t *b, int *l, uint64_t v) { for (int i = 0; i < 8; i++) put1(b, l, (v >> (8*i)) & 0xff); }
static void put_varint(uint8_t *b, int *l, uint64_t v) {
    if (v < 0xFD) put1(b, l, (int)v);
    else if (v <= 0xFFFF) { put1(b, l, 0xFD); put1(b, l, v & 0xff); put1(b, l, (v >> 8) & 0xff); }
    else { put1(b, l, 0xFE); put_u32le(b, l, (uint32_t)v); }
}
static void emit_push(uint8_t *b, int *l, const uint8_t *d, int dlen) {  // minimal push
    if (dlen < 76) put1(b, l, dlen);
    else if (dlen <= 255) { put1(b, l, 0x4c); put1(b, l, dlen); }
    else { put1(b, l, 0x4d); put1(b, l, dlen & 0xff); put1(b, l, (dlen >> 8) & 0xff); }
    put(b, l, d, dlen);
}

// ── parsed tx + attribution ───────────────────────────────────────────────────
#define MAX_IN 4
#define MAX_OUT 4
typedef struct { uint8_t outpoint[36]; const uint8_t *ss; int sslen; uint32_t seq; } AIn;
typedef struct { uint64_t value; const uint8_t *spk; int spklen; } AOut;
typedef struct { uint32_t version; int n_in; AIn in[MAX_IN]; int n_out; AOut out[MAX_OUT]; uint32_t locktime; } ATx;

// returns 1 on parse ok (pointers into raw), 0 on malformed/witness.
static int tx_parse(const uint8_t *raw, int n, ATx *t) {
    int pos = 0;
    if (n < 10) return 0;
    if (raw[4] == 0x00 && raw[5] == 0x01) return 0;       // reject witness marker
    t->version = raw[pos] | (raw[pos+1] << 8) | (raw[pos+2] << 16) | ((uint32_t)raw[pos+3] << 24); pos += 4;
    if (raw[pos] >= 0xFD) return 0; int nin = raw[pos++];  // counts pinned < 0xFD by generator
    if (nin < 1 || nin > MAX_IN) return 0; t->n_in = nin;
    for (int i = 0; i < nin; i++) {
        if (pos + 36 > n) return 0; memcpy(t->in[i].outpoint, raw + pos, 36); pos += 36;
        if (pos >= n || raw[pos] >= 0xFD) return 0; int sl = raw[pos++];
        if (pos + sl > n) return 0; t->in[i].ss = raw + pos; t->in[i].sslen = sl; pos += sl;
        if (pos + 4 > n) return 0;
        t->in[i].seq = raw[pos] | (raw[pos+1]<<8) | (raw[pos+2]<<16) | ((uint32_t)raw[pos+3]<<24); pos += 4;
    }
    if (pos >= n || raw[pos] >= 0xFD) return 0; int nout = raw[pos++];
    if (nout < 1 || nout > MAX_OUT) return 0; t->n_out = nout;
    for (int j = 0; j < nout; j++) {
        if (pos + 8 > n) return 0; uint64_t v = 0; for (int k = 0; k < 8; k++) v |= (uint64_t)raw[pos+k] << (8*k);
        pos += 8; t->out[j].value = v;
        if (pos >= n || raw[pos] >= 0xFD) return 0; int sl = raw[pos++];
        if (pos + sl > n) return 0; t->out[j].spk = raw + pos; t->out[j].spklen = sl; pos += sl;
    }
    if (pos + 4 > n) return 0;
    t->locktime = raw[pos] | (raw[pos+1]<<8) | (raw[pos+2]<<16) | ((uint32_t)raw[pos+3]<<24); pos += 4;
    return pos == n;
}

// legacy sighash for input k with the given (FindAndDelete-applied) scriptCode.
static void legacy_sighash(const ATx *t, int k, const uint8_t *scriptCode, int scLen, uint8_t out[32]) {
    uint8_t b[8192]; int l = 0;
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
    put_u32le(b, &l, 0x00000001);                          // SIGHASH_ALL
    sha256d(b, l, out);
}

typedef struct { int status; uint8_t sighash[32]; uint8_t identity[20]; } AResult;
// status: 0 classify-drop, 1 oncurve-drop, 2 verify-drop, 3 found
enum { ST_CLASSIFY = 0, ST_ONCURVE = 1, ST_VERIFY = 2, ST_FOUND = 3 };

typedef struct { uint8_t r[32], s[32]; const uint8_t *data; int dlen; } ASig;

// Curve oracle selector: 0 = injected pseudo-funcs (Tier-1 self-regression; the
// `attrib`/`attrib-scenario` frozen goldens), 1 = REAL secp256k1 (the §4 Strategy B
// end-to-end vectors in attrib-curve). attrib/attrib-scenario never flip this, so
// their goldens stay byte-identical — the seam §3/§5 of the handoff plan describes.
static int g_real_curve = 0;
static int oc_gate(const uint8_t *pub, int plen) {
    return g_real_curve ? secp_on_curve(pub, plen) : inj_on_curve(pub, plen);
}
static int vf_gate(const uint8_t h[32], const uint8_t r[32], const uint8_t s[32], const uint8_t *pub, int plen) {
    return g_real_curve ? secp_ecdsa_verify(h, r, s, pub, plen) : inj_verify(h, r, s, pub, plen);
}

static void attribute(const ATx *t, int k, AResult *res) {
    memset(res, 0, sizeof *res);
    const uint8_t *ss = t->in[k].ss; int n = t->in[k].sslen;

    // 1. parse top-level pushes (minimal)
    int op[32]; const uint8_t *dat[32]; int dl[32], cnt = 0, pos = 0;
    while (pos < n) {
        if (cnt >= 32) { res->status = ST_CLASSIFY; return; }
        if (!take_push(ss, n, &pos, &op[cnt], &dat[cnt], &dl[cnt])) { res->status = ST_CLASSIFY; return; }
        cnt++;
    }

    int kind = 0;                                          // 1=P2PKH, 2=MULTISIG
    ASig sigs[15]; int nsig = 0;
    const uint8_t *pubkey = NULL; int publen = 0;
    uint8_t keys[15][33]; int nkeys = 0;
    uint8_t scriptCode[8192]; int scLen = 0;

    // 2. P2PKH: exactly [sig][pubkey]
    if (cnt == 2 && op[0] != 0x00 && op[1] != 0x00 &&
        der_parse(dat[0], dl[0], sigs[0].r, sigs[0].s) && pub_enc_ok(dat[1], dl[1])) {
        kind = 1; nsig = 1; sigs[0].data = dat[0]; sigs[0].dlen = dl[0];
        pubkey = dat[1]; publen = dl[1];
        hash160(pubkey, publen, res->identity);
        // scriptCode = OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
        scLen = 0; put1(scriptCode, &scLen, 0x76); put1(scriptCode, &scLen, 0xa9);
        put1(scriptCode, &scLen, 0x14); put(scriptCode, &scLen, res->identity, 20);
        put1(scriptCode, &scLen, 0x88); put1(scriptCode, &scLen, 0xac);
    }
    // 3. P2SH multisig: OP_0 [sig]xm [redeemScript]
    else if (cnt >= 3 && op[0] == 0x00 && dl[0] == 0) {
        int m, nk;
        if (rs_template(dat[cnt - 1], dl[cnt - 1], &m, &nk, keys) && (cnt - 2) == m) {
            int ok = 1;
            for (int i = 0; i < m; i++) {
                if (op[1 + i] == 0x00 || !der_parse(dat[1 + i], dl[1 + i], sigs[i].r, sigs[i].s)) { ok = 0; break; }
                sigs[i].data = dat[1 + i]; sigs[i].dlen = dl[1 + i];
            }
            if (ok) {
                kind = 2; nsig = m; nkeys = nk;
                hash160(dat[cnt - 1], dl[cnt - 1], res->identity);
                scLen = dl[cnt - 1]; memcpy(scriptCode, dat[cnt - 1], (size_t)scLen);
            }
        }
    }
    if (kind == 0) { res->status = ST_CLASSIFY; return; }

    // 4. sighash: FindAndDelete each sig push from scriptCode, then legacy sighash
    for (int i = 0; i < nsig; i++) {
        uint8_t pat[80]; int pl = 0; emit_push(pat, &pl, sigs[i].data, sigs[i].dlen);
        find_and_delete(scriptCode, &scLen, pat, pl);
    }
    legacy_sighash(t, k, scriptCode, scLen, res->sighash);

    // 5. on-curve gate (injected pseudo-func, or real secp256k1 when g_real_curve)
    if (kind == 1) { if (!oc_gate(pubkey, publen)) { res->status = ST_ONCURVE; return; } }
    else { for (int i = 0; i < nkeys; i++) if (!oc_gate(keys[i], 33)) { res->status = ST_ONCURVE; return; } }

    // 6. verify (injected/real); multisig = in-order subsequence scan
    int ok;
    if (kind == 1) ok = vf_gate(res->sighash, sigs[0].r, sigs[0].s, pubkey, publen);
    else {
        int si = 0, ki = 0;
        while (si < nsig && ki < nkeys) {
            if (vf_gate(res->sighash, sigs[si].r, sigs[si].s, keys[ki], 33)) { si++; ki++; }
            else ki++;
        }
        ok = (si == nsig);
    }
    res->status = ok ? ST_FOUND : ST_VERIFY;
}

// ── generator (raw tx bytes; pinned draw order) ───────────────────────────────
typedef struct { SmRng rng; uint8_t *ih_active; } G;
static uint64_t bnd(SmRng *r, uint64_t n) { return sm_rng_bounded(r, n); }
static int byte(SmRng *r) { return (int)sm_rng_bounded(r, 256); }

// emit a valid-or-defective DER sig push DATA (der ‖ sighash) into sig/&sl
static void gen_sig(SmRng *r, int defect, uint8_t *sig, int *sl) {
    uint8_t R[32], S[32];
    R[0] = (uint8_t)bnd(r, 0x80); for (int i = 1; i < 32; i++) R[i] = (uint8_t)byte(r);
    if (R[0] == 0) R[0] = 1;
    S[0] = (uint8_t)(1 + bnd(r, 0x3E)); for (int i = 1; i < 32; i++) S[i] = (uint8_t)byte(r);
    *sl = 0;
    put1(sig, sl, 0x30); put1(sig, sl, 0x44);
    put1(sig, sl, 0x02); put1(sig, sl, 0x20); put(sig, sl, R, 32);
    put1(sig, sl, 0x02); put1(sig, sl, 0x20); put(sig, sl, S, 32);
    put1(sig, sl, 0x01);                                  // sighash type
    if (defect == 1) sig[0] = 0x31;                        // bad SEQUENCE tag
    else if (defect == 2) sig[*sl - 1] = (uint8_t)(byte(r) | 0x80);   // wrong sighash type (ANYONECANPAY-ish)
    else if (defect == 3) sig[4] = 0x80;                   // R high bit set → negative
    else if (defect == 4) { put1(sig, sl, byte(r)); }      // trailing byte → length mismatch
    else if (defect == 5) sig[1] = 0x45;                   // length byte wrong
}

static void gen_pubkey(SmRng *r, int kind, uint8_t *pub, int *pl) {
    *pl = 0;
    if (kind == 0) { put1(pub, pl, 0x02 + (int)bnd(r, 2)); pub[1] = (uint8_t)bnd(r, 0xFF);
        for (int i = 2; i < 33; i++) pub[i] = (uint8_t)byte(r); *pl = 33; }
    else if (kind == 1) { put1(pub, pl, 0x04); pub[1] = (uint8_t)bnd(r, 0xFF);
        for (int i = 2; i < 33; i++) pub[i] = (uint8_t)byte(r);
        pub[33] = (uint8_t)bnd(r, 0xFF); for (int i = 34; i < 65; i++) pub[i] = (uint8_t)byte(r); *pl = 65; }
    else if (kind == 2) { put1(pub, pl, 0x06); for (int i = 1; i < 65; i++) pub[i] = (uint8_t)byte(r); *pl = 65; }  // hybrid
    else if (kind == 3) { for (int i = 0; i < 32; i++) pub[i] = (uint8_t)byte(r); *pl = 32; }                       // bad len
    else { put1(pub, pl, 0x02 + (int)bnd(r, 2)); for (int i = 1; i < 33; i++) pub[i] = 0xFF; *pl = 33; }            // X >= p
}

// emit a redeemScript blob (valid or defective) into rs/&rl, m/n echoed.
static void gen_redeemscript(SmRng *r, int valid, uint8_t *rs, int *rl, int *m_out, int *n_out) {
    int m = 1 + (int)bnd(r, 3);
    int n = m + (int)bnd(r, 4);                            // n in [m, m+3], capped below
    if (n > 8) n = 8;
    *rl = 0; put1(rs, rl, 0x50 + m);
    int badkey = !valid && bnd(r, 2) == 0;
    for (int i = 0; i < n; i++) {
        if (badkey && i == 0) { put1(rs, rl, 0x41); put1(rs, rl, 0x04);  // uncompressed key in template
            for (int j = 0; j < 64; j++) put1(rs, rl, byte(r)); }
        else { put1(rs, rl, 0x21); put1(rs, rl, 0x02 + (int)bnd(r, 2));
            rs[*rl] = (uint8_t)bnd(r, 0xFF); (*rl)++; for (int j = 2; j < 33; j++) put1(rs, rl, byte(r)); }
    }
    put1(rs, rl, 0x50 + n);
    if (valid || bnd(r, 2) == 0) put1(rs, rl, 0xAE);       // OP_CHECKMULTISIG (drop sometimes)
    else put1(rs, rl, byte(r));
    if (!valid && !badkey) put1(rs, rl, byte(r));          // trailing byte
    *m_out = m; *n_out = n;
}

static void gen_scriptsig(SmRng *r, uint8_t *ss, int *sl) {
    *sl = 0;
    int kind = (int)bnd(r, 10);
    uint8_t sig[128], pub[80], rs[600];
    int sigl, publ, rl, m, n;
    if (kind <= 2) {                                       // P2PKH valid
        gen_sig(r, 0, sig, &sigl); emit_push(ss, sl, sig, sigl);
        gen_pubkey(r, (int)bnd(r, 2), pub, &publ); emit_push(ss, sl, pub, publ);
    } else if (kind == 3) {                                // P2PKH bad DER
        gen_sig(r, 1 + (int)bnd(r, 5), sig, &sigl); emit_push(ss, sl, sig, sigl);
        gen_pubkey(r, 0, pub, &publ); emit_push(ss, sl, pub, publ);
    } else if (kind == 4) {                                // P2PKH bad pubkey
        gen_sig(r, 0, sig, &sigl); emit_push(ss, sl, sig, sigl);
        gen_pubkey(r, 2 + (int)bnd(r, 3), pub, &publ); emit_push(ss, sl, pub, publ);
    } else if (kind == 5) {                                // P2PKH non-minimal pubkey push
        gen_sig(r, 0, sig, &sigl); emit_push(ss, sl, sig, sigl);
        gen_pubkey(r, 0, pub, &publ); put1(ss, sl, 0x4c); put1(ss, sl, publ); put(ss, sl, pub, publ);
    } else if (kind <= 7) {                                // multisig valid
        gen_redeemscript(r, 1, rs, &rl, &m, &n);
        put1(ss, sl, 0x00);
        for (int i = 0; i < m; i++) { gen_sig(r, 0, sig, &sigl); emit_push(ss, sl, sig, sigl); }
        emit_push(ss, sl, rs, rl);
    } else if (kind == 8) {                                // multisig bad
        int sub = (int)bnd(r, 4);
        gen_redeemscript(r, sub == 0 ? 1 : 0, rs, &rl, &m, &n);
        put1(ss, sl, sub == 1 ? 0x51 : 0x00);              // sub==1: NULLDUMMY wrong (OP_1)
        int emit = m + (sub == 2 ? 1 : 0) - (sub == 3 ? 1 : 0);  // sub 2/3: sig count mismatch
        if (emit < 0) emit = 0;
        for (int i = 0; i < emit; i++) { gen_sig(r, 0, sig, &sigl); emit_push(ss, sl, sig, sigl); }
        emit_push(ss, sl, rs, rl);
    } else {                                               // garbage
        int gl = (int)bnd(r, 40);
        for (int i = 0; i < gl; i++) put1(ss, sl, byte(r));
    }
}

static uint32_t gen_u32(SmRng *r) { uint32_t v = 0; for (int i = 0; i < 4; i++) v |= (uint32_t)byte(r) << (8 * i); return v; }

static uint64_t gen_value(SmRng *r) {
    int sel = (int)bnd(r, 4);
    if (sel == 0) return 0;
    if (sel == 1) return 0xFFFFFFFFFFFFFFFFULL - bnd(r, 1000);
    return 1 + bnd(r, 1000000);
}

static void gen_tx(SmRng *r, uint8_t *raw, int *rawlen) {
    int l = 0;
    put_u32le(raw, &l, 1 + (uint32_t)bnd(r, 2));
    int nin = 1 + (int)bnd(r, 3); put_varint(raw, &l, (uint64_t)nin);
    for (int i = 0; i < nin; i++) {
        for (int j = 0; j < 36; j++) put1(raw, &l, byte(r));        // outpoint
        uint8_t ss[2048]; int sl; gen_scriptsig(r, ss, &sl);
        put_varint(raw, &l, (uint64_t)sl); put(raw, &l, ss, sl);
        uint32_t seq = bnd(r, 4) == 0 ? gen_u32(r) : 0xFFFFFFFF;
        put_u32le(raw, &l, seq);
    }
    int nout = 1 + (int)bnd(r, 3); put_varint(raw, &l, (uint64_t)nout);
    for (int j = 0; j < nout; j++) {
        put_u64le(raw, &l, gen_value(r));
        int spkl = 1 + (int)bnd(r, 33); put_varint(raw, &l, (uint64_t)spkl);
        for (int i = 0; i < spkl; i++) put1(raw, &l, byte(r));
    }
    uint32_t lt = bnd(r, 2) == 0 ? 0 : gen_u32(r);
    put_u32le(raw, &l, lt);
    *rawlen = l;
}

// ── the differential fuzz driver ──────────────────────────────────────────────
static int attrib_run(uint64_t seed, int count, int show_cov) {
    SmRng rng; sm_rng_seed(&rng, seed);
    SHA256_CTX ih, sh; sha256_init(&ih); sha256_init(&sh);
    long cov[6] = {0,0,0,0,0,0};                            // classify, oncurve, verify, found, p2pkh, multisig
    for (int c = 0; c < count; c++) {
        uint8_t raw[4096]; int rawlen; gen_tx(&rng, raw, &rawlen);
        uint8_t lp[4]; lp[0]=rawlen&0xff; lp[1]=(rawlen>>8)&0xff; lp[2]=(rawlen>>16)&0xff; lp[3]=(rawlen>>24)&0xff;
        sha256_update(&ih, lp, 4); sha256_update(&ih, raw, (unsigned)rawlen);
        ATx t;
        if (!tx_parse(raw, rawlen, &t)) { uint8_t z = 0xFF; sha256_update(&sh, &z, 1); continue; }
        for (int k = 0; k < t.n_in; k++) {
            AResult res; attribute(&t, k, &res);
            uint8_t rec[1 + 1 + 32 + 20]; int rl = 0;
            rec[rl++] = (uint8_t)k; rec[rl++] = (uint8_t)res.status;
            memcpy(rec + rl, res.sighash, 32); rl += 32;
            memcpy(rec + rl, res.identity, 20); rl += 20;
            sha256_update(&sh, rec, (unsigned)rl);
            cov[res.status]++;
        }
    }
    uint8_t id[32], sd[32]; sha256_final(&ih, id); sha256_final(&sh, sd);
    char hx[65];
    printf("txs=%d\n", count);
    { char b[65]; for (int i=0;i<32;i++){ static const char*H="0123456789abcdef"; b[2*i]=H[id[i]>>4]; b[2*i+1]=H[id[i]&15]; } b[64]='\0'; printf("input_digest=%s\n", b); }
    { for (int i=0;i<32;i++){ static const char*H="0123456789abcdef"; hx[2*i]=H[sd[i]>>4]; hx[2*i+1]=H[sd[i]&15]; } hx[64]='\0'; printf("state_digest=%s\n", hx); }
    if (show_cov)
        printf("attrib_cov: classify_drop=%ld oncurve_drop=%ld verify_drop=%ld found=%ld\n",
               cov[0], cov[1], cov[2], cov[3]);
    return 0;
}

int attrib_cmd_fuzz(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: sm attrib <seed> <count> [--cov]\n"); return 2; }
    uint64_t seed = strtoull(argv[2], NULL, 0); int count = atoi(argv[3]);
    int cov = (argc > 4 && strcmp(argv[4], "--cov") == 0);
    return attrib_run(seed, count, cov);
}

// ── directed scenario vectors (hand-authored, auditable) ──────────────────────
static void hx32(const uint8_t *d, char *o) { static const char*H="0123456789abcdef"; for(int i=0;i<32;i++){o[2*i]=H[d[i]>>4];o[2*i+1]=H[d[i]&15];} o[64]='\0'; }

int attrib_cmd_scenario(int argc, char **argv) {
    (void)argc; (void)argv;
    SHA256_CTX comb; sha256_init(&comb);
    // Each vector: build a raw tx, attribute vin0, print "name <status> <identity-hex>".
    // ripemd160 KAT first (anchors the Identity hash across languages).
    uint8_t h[20]; char hb[41]; static const char *H = "0123456789abcdef";
    ripemd160((const uint8_t*)"", 0, h);
    for (int i=0;i<20;i++){hb[2*i]=H[h[i]>>4];hb[2*i+1]=H[h[i]&15];} hb[40]='\0';
    printf("00_ripemd_empty %s\n", hb); sha256_update(&comb, h, 20);
    ripemd160((const uint8_t*)"abc", 3, h);
    for (int i=0;i<20;i++){hb[2*i]=H[h[i]>>4];hb[2*i+1]=H[h[i]&15];} hb[40]='\0';
    printf("01_ripemd_abc %s\n", hb); sha256_update(&comb, h, 20);

    // A reproducible signed-ish tx via the generator at a few fixed seeds (their
    // attribute() results are auditable + frozen). Cross-checked by every language.
    for (int s = 0; s < 16; s++) {
        SmRng rng; sm_rng_seed(&rng, 0xA77216 + (uint64_t)s);
        uint8_t raw[4096]; int rawlen; gen_tx(&rng, raw, &rawlen);
        ATx t; char line[160]; int ll = 0;
        ll += sprintf(line + ll, "vec%02d", s);
        if (tx_parse(raw, rawlen, &t)) {
            for (int k = 0; k < t.n_in; k++) {
                AResult res; attribute(&t, k, &res);
                char idh[41]; for (int i=0;i<20;i++){idh[2*i]=H[res.identity[i]>>4];idh[2*i+1]=H[res.identity[i]&15];} idh[40]='\0';
                ll += sprintf(line + ll, " k%d=%d:%s", k, res.status, idh);
                sha256_update(&comb, (uint8_t*)&res.status, 1);
                sha256_update(&comb, res.sighash, 32);
                sha256_update(&comb, res.identity, 20);
            }
        } else { ll += sprintf(line + ll, " parsefail"); uint8_t z=0xFF; sha256_update(&comb, &z, 1); }
        printf("%s\n", line);
    }
    // ── FindAndDelete vectors (pin it CROSS-LANGUAGE). On the rigid compressed-key
    //    template FindAndDelete is structurally inert (a 33-byte key push never collides
    //    with a sig push at an opcode boundary), so without these a port could omit it
    //    entirely and still match every digest. These make it non-omittable. ──
    {
        // boundary removal: two pushes of {02 AA BB} deleted; the OP bytes 51/52/AE stay.
        uint8_t s1[] = {0x51, 0x02,0xAA,0xBB, 0x52, 0x02,0xAA,0xBB, 0xAE}; int l1 = (int)sizeof s1;
        uint8_t p1[] = {0x02,0xAA,0xBB}; find_and_delete(s1, &l1, p1, 3);
        printf("fad00_boundary "); for (int i=0;i<l1;i++) printf("%02x", s1[i]); printf("\n");
        sha256_update(&comb, s1, (unsigned)l1);
        // non-boundary: the pattern sits inside a 4-byte push body → NOT removed.
        uint8_t s2[] = {0x04, 0x02,0xAA,0xBB,0xCC, 0xAE}; int l2 = (int)sizeof s2;
        uint8_t p2[] = {0x02,0xAA,0xBB}; find_and_delete(s2, &l2, p2, 3);
        printf("fad01_inbody "); for (int i=0;i<l2;i++) printf("%02x", s2[i]); printf("\n");
        sha256_update(&comb, s2, (unsigned)l2);
        // load-bearing: sighash WITH vs WITHOUT FaD on a scriptCode that contains the pattern
        // at a boundary MUST differ (proves FaD changes the preimage, not just cosmetics).
        ATx t; memset(&t, 0, sizeof t); t.version = 1; t.n_in = 1; t.n_out = 1;
        t.in[0].seq = 0xFFFFFFFF; static const uint8_t spk0[1] = {0x6a};
        t.out[0].value = 0; t.out[0].spk = spk0; t.out[0].spklen = 1; t.locktime = 0;
        uint8_t sc[] = {0x51, 0x02,0xAA,0xBB, 0xAC}; int scl = (int)sizeof sc;
        uint8_t sh_no[32]; legacy_sighash(&t, 0, sc, scl, sh_no);
        uint8_t scd[16]; int scdl = scl; memcpy(scd, sc, (size_t)scl);
        uint8_t pat[] = {0x02,0xAA,0xBB}; find_and_delete(scd, &scdl, pat, 3);
        uint8_t sh_fd[32]; legacy_sighash(&t, 0, scd, scdl, sh_fd);
        char aa[65], bb[65]; hx32(sh_no, aa); hx32(sh_fd, bb);
        printf("fad02_sighash_nofad %s\n", aa); printf("fad03_sighash_fad %s\n", bb);
        sha256_update(&comb, sh_no, 32); sha256_update(&comb, sh_fd, 32);
    }

    // ── §3.10 wallet-preview vectors (a conformance artifact, not prose): raw tx →
    //    {per-input attribution; for each TRADE the exact (give, get) per party}. We render a
    //    TRADE(idx_a=0, idx_b=1, nameA="alpha", nameB="beta"): vin0's identity gives alpha /
    //    gets beta; vin1's gives beta / gets alpha. The give/get DIRECTION is the safety-
    //    relevant rendering a wallet must show before an irreversible swap. ──
    int pv = 0;
    for (int s = 0; pv < 6 && s < 256; s++) {
        SmRng rng; sm_rng_seed(&rng, 0x9E711E + (uint64_t)s);
        uint8_t raw[4096]; int rawlen; gen_tx(&rng, raw, &rawlen);
        ATx t;
        if (!tx_parse(raw, rawlen, &t) || t.n_in < 2) continue;   // need ≥2 parties to render a TRADE
        AResult ra, rb; attribute(&t, 0, &ra); attribute(&t, 1, &rb);
        char ida[41], idb[41];
        for (int i=0;i<20;i++){ida[2*i]=H[ra.identity[i]>>4];ida[2*i+1]=H[ra.identity[i]&15];} ida[40]='\0';
        for (int i=0;i<20;i++){idb[2*i]=H[rb.identity[i]>>4];idb[2*i+1]=H[rb.identity[i]&15];} idb[40]='\0';
        printf("prev%02d A=%d:%s:give=alpha,get=beta B=%d:%s:give=beta,get=alpha\n", pv, ra.status, ida, rb.status, idb);
        sha256_update(&comb, (uint8_t*)&ra.status, 1); sha256_update(&comb, ra.identity, 20);
        sha256_update(&comb, (const uint8_t*)"alpha", 5); sha256_update(&comb, (const uint8_t*)"beta", 4);
        sha256_update(&comb, (uint8_t*)&rb.status, 1); sha256_update(&comb, rb.identity, 20);
        sha256_update(&comb, (const uint8_t*)"beta", 4); sha256_update(&comb, (const uint8_t*)"alpha", 5);
        pv++;
    }

    // ── A7 vector (off-curve P2PKH ⇒ on-curve-drop). The clean-room Rust audit
    //    (finding A7) diverged HERE: a well-ENCODED but OFF-curve P2PKH pubkey must
    //    classify as status 1 (on-curve-drop), exactly like a multisig redeemScript
    //    key — §4 Rule 4 "non-canonical → drop" + §13. The generated soak almost
    //    never lands a canonical-encoding-but-off-curve compressed key on the P2PKH
    //    path (it only exercised the curve gate via multisig), so the prose gap that
    //    produced A7 was invisible to the digests. Two minimal P2PKH inputs share one
    //    valid (low-S, SIGHASH_ALL) DER sig — one off-curve, one on-curve — pinning
    //    that the step-5 on-curve gate (attribute()) is what flips the verdict. ──
    {
        // minimal valid DER sig push-DATA: SEQ{ INT 0x01, INT 0x01 } ‖ SIGHASH_ALL.
        static const uint8_t sig[9] = {0x30,0x06,0x02,0x01,0x01,0x02,0x01,0x01,0x01};
        // find a canonical compressed pubkey (0x02 ‖ X, X<p) OFF the injected curve,
        // and (separately) one ON it. pk[1]=0 ⇒ X<p always, so pub_enc_ok holds.
        uint8_t off[33], on[33]; int have_off = 0, have_on = 0;
        for (uint32_t c = 0; (!have_off || !have_on) && c < 1000000u; c++) {
            uint8_t pk[33]; pk[0] = 0x02; memset(pk + 1, 0, 32);
            pk[29]=(uint8_t)(c>>24); pk[30]=(uint8_t)(c>>16); pk[31]=(uint8_t)(c>>8); pk[32]=(uint8_t)c;
            if (!pub_enc_ok(pk, 33)) continue;
            if (!inj_on_curve(pk, 33)) { if (!have_off) { memcpy(off, pk, 33); have_off = 1; } }
            else                       { if (!have_on)  { memcpy(on,  pk, 33); have_on  = 1; } }
        }
        int fail = 0;
        if (!have_off || !have_on) { fprintf(stderr, "FAIL: A7 no off/on-curve canonical pubkey found\n"); fail = 1; }
        const char *names[2] = {"a7off_p2pkh_offcurve", "a7on_p2pkh_oncurve"};
        const uint8_t *pks[2] = {off, on};
        for (int v = 0; v < 2; v++) {
            uint8_t ss[64]; int ssl = 0; emit_push(ss, &ssl, sig, 9); emit_push(ss, &ssl, pks[v], 33);
            uint8_t raw[256]; int l = 0;
            put_u32le(raw, &l, 1); put_varint(raw, &l, 1);
            for (int i = 0; i < 36; i++) put1(raw, &l, 0x00);
            put_varint(raw, &l, (uint64_t)ssl); put(raw, &l, ss, ssl); put_u32le(raw, &l, 0xFFFFFFFF);
            put_varint(raw, &l, 1); put_u64le(raw, &l, 0); put_varint(raw, &l, 1); put1(raw, &l, 0x6a);
            put_u32le(raw, &l, 0);
            ATx t; AResult res; memset(&res, 0, sizeof res);
            if (!tx_parse(raw, l, &t)) { fprintf(stderr, "FAIL: A7 %s tx_parse\n", names[v]); fail = 1; }
            else attribute(&t, 0, &res);
            char idh[41]; for (int i=0;i<20;i++){idh[2*i]=H[res.identity[i]>>4];idh[2*i+1]=H[res.identity[i]&15];} idh[40]='\0';
            printf("%s %d:%s\n", names[v], res.status, idh);
            sha256_update(&comb, (uint8_t*)&res.status, 1);
            sha256_update(&comb, res.sighash, 32);
            sha256_update(&comb, res.identity, 20);
            if (v == 0 && res.status != ST_ONCURVE)
                { fprintf(stderr, "FAIL: A7 off-curve P2PKH status=%d, want 1 (on-curve-drop)\n", res.status); fail = 1; }
            if (v == 1 && res.status == ST_ONCURVE)
                { fprintf(stderr, "FAIL: A7 on-curve P2PKH wrongly dropped at the curve gate\n"); fail = 1; }
        }
        if (fail) return 1;
    }

    uint8_t cd[32]; sha256_final(&comb, cd); char cb[65]; hx32(cd, cb);
    printf("combined %s\n", cb);
    return 0;
}

// ── §4 Strategy B: end-to-end REAL-curve pipeline vectors ─────────────────────
// Build a transaction, compute its genuine legacy sighash, sign THAT with RFC-6979,
// embed the signature, and run the full attribute() pipeline with the real curve.
// This pins the load-bearing linkage the curve-vector battery alone can't: that the
// message fed to ecdsa_verify IS the shell's computed sighash. Cross-language: every
// impl reproduces these (status, identity) outcomes byte-for-byte.
static int der_int_e(uint8_t *out, const uint8_t v[32]) {
    int i = 0; while (i < 31 && v[i] == 0) i++;
    int len = 32 - i, pad = (v[i] & 0x80) ? 1 : 0;
    out[0] = 0x02; out[1] = (uint8_t)(len + pad); int n = 2;
    if (pad) out[n++] = 0x00;
    memcpy(out + n, v + i, (size_t)len); n += len;
    return n;
}
static int der_sig_e(uint8_t *out, const uint8_t r[32], const uint8_t s[32]) {
    uint8_t body[80]; int bl = 0;
    bl += der_int_e(body + bl, r); bl += der_int_e(body + bl, s);
    out[0] = 0x30; out[1] = (uint8_t)bl; memcpy(out + 2, body, (size_t)bl);
    out[2 + bl] = 0x01; return 2 + bl + 1;
}
// shared tx skeleton: 1 input (fixed outpoint 0x11.., seq=FFFFFFFF), 1 output
// (value=100000, scriptPubKey=OP_RETURN), version 1, locktime 0.
static void e2e_skeleton(ATx *t) {
    static const uint8_t spk[1] = { 0x6a };
    memset(t, 0, sizeof *t);
    t->version = 1; t->n_in = 1; t->n_out = 1;
    memset(t->in[0].outpoint, 0x11, 36); t->in[0].seq = 0xFFFFFFFF;
    t->out[0].value = 100000; t->out[0].spk = spk; t->out[0].spklen = 1; t->locktime = 0;
}
// assemble raw tx bytes carrying the given scriptSig (same structural fields as the
// skeleton, so attribute()'s recomputed sighash equals the one we signed).
static int e2e_rawtx(uint8_t *raw, const uint8_t *ss, int sslen) {
    int l = 0;
    put_u32le(raw, &l, 1); put_varint(raw, &l, 1);
    for (int i = 0; i < 36; i++) put1(raw, &l, 0x11);
    put_varint(raw, &l, (uint64_t)sslen); put(raw, &l, ss, sslen);
    put_u32le(raw, &l, 0xFFFFFFFF);
    put_varint(raw, &l, 1); put_u64le(raw, &l, 100000); put_varint(raw, &l, 1); put1(raw, &l, 0x6a);
    put_u32le(raw, &l, 0);
    return l;
}
void attrib_real_endtoend(void *comb_ctx) {
    SHA256_CTX *comb = (SHA256_CTX *)comb_ctx;
    static const char *H = "0123456789abcdef";
    g_real_curve = 1;

    // helper to print + fold one attributed input
    #define EMIT_E2E(name, t_, k_) do { \
        AResult res; attribute((t_), (k_), &res); \
        char idh[41]; for (int i=0;i<20;i++){idh[2*i]=H[res.identity[i]>>4];idh[2*i+1]=H[res.identity[i]&15];} idh[40]='\0'; \
        printf("%s %d:%s\n", (name), res.status, idh); \
        sha256_update(comb, (uint8_t*)&res.status, 1); \
        sha256_update(comb, res.sighash, 32); sha256_update(comb, res.identity, 20); \
    } while (0)

    // ── A. P2PKH, correctly signed ⇒ FOUND ─────────────────────────────────────
    {
        uint8_t priv[32]; memset(priv, 0, 32); priv[31] = 0x2A;       // priv = 42
        uint8_t pub[33]; secp_pubkey(priv, pub);
        uint8_t h160[20]; hash160(pub, 33, h160);
        uint8_t sc[64]; int scl = 0;                                  // standard P2PKH scriptCode
        put1(sc,&scl,0x76); put1(sc,&scl,0xa9); put1(sc,&scl,0x14); put(sc,&scl,h160,20); put1(sc,&scl,0x88); put1(sc,&scl,0xac);
        ATx sk; e2e_skeleton(&sk);
        uint8_t sh[32]; legacy_sighash(&sk, 0, sc, scl, sh);
        uint8_t r[32], s[32]; secp_ecdsa_sign(priv, sh, r, s);
        uint8_t der[80]; int dl = der_sig_e(der, r, s);
        uint8_t ss[160]; int ssl = 0; emit_push(ss,&ssl,der,dl); emit_push(ss,&ssl,pub,33);
        uint8_t raw[256]; int rl = e2e_rawtx(raw, ss, ssl);
        ATx t; if (tx_parse(raw, rl, &t)) EMIT_E2E("e2e_p2pkh_valid", &t, 0);
        else { printf("e2e_p2pkh_valid PARSEFAIL\n"); }
    }
    // ── B. P2PKH, signed by the WRONG key ⇒ verify-drop (status 2) ──────────────
    {
        uint8_t priv[32]; memset(priv, 0, 32); priv[31] = 0x2A;
        uint8_t wrong[32]; memset(wrong, 0, 32); wrong[31] = 0x2B;     // different signer
        uint8_t pub[33]; secp_pubkey(priv, pub);
        uint8_t h160[20]; hash160(pub, 33, h160);
        uint8_t sc[64]; int scl = 0;
        put1(sc,&scl,0x76); put1(sc,&scl,0xa9); put1(sc,&scl,0x14); put(sc,&scl,h160,20); put1(sc,&scl,0x88); put1(sc,&scl,0xac);
        ATx sk; e2e_skeleton(&sk);
        uint8_t sh[32]; legacy_sighash(&sk, 0, sc, scl, sh);
        uint8_t r[32], s[32]; secp_ecdsa_sign(wrong, sh, r, s);        // wrong key signs
        uint8_t der[80]; int dl = der_sig_e(der, r, s);
        uint8_t ss[160]; int ssl = 0; emit_push(ss,&ssl,der,dl); emit_push(ss,&ssl,pub,33);
        uint8_t raw[256]; int rl = e2e_rawtx(raw, ss, ssl);
        ATx t; if (tx_parse(raw, rl, &t)) EMIT_E2E("e2e_p2pkh_wrongkey", &t, 0);
        else { printf("e2e_p2pkh_wrongkey PARSEFAIL\n"); }
    }
    // ── C. 2-of-2 P2SH multisig, two correct in-order sigs ⇒ FOUND. (2-of-2 keeps
    //    the scriptSig under tx_parse's single-byte length cap of 252.) ───────────
    {
        uint8_t priv[2][32], pub[2][33];
        for (int i = 0; i < 2; i++) { memset(priv[i], 0, 32); priv[i][31] = (uint8_t)(0x50 + i); secp_pubkey(priv[i], pub[i]); }
        uint8_t rs[120]; int rl = 0;                                  // OP_2 <k0><k1> OP_2 OP_CHECKMULTISIG
        put1(rs,&rl,0x52);
        for (int i = 0; i < 2; i++) { put1(rs,&rl,0x21); put(rs,&rl,pub[i],33); }
        put1(rs,&rl,0x52); put1(rs,&rl,0xae);
        ATx sk; e2e_skeleton(&sk);
        uint8_t sh[32]; legacy_sighash(&sk, 0, rs, rl, sh);
        uint8_t ss[400]; int ssl = 0; put1(ss,&ssl,0x00);             // NULLDUMMY
        for (int i = 0; i < 2; i++) {                                 // sign with keys 0,1 (in order)
            uint8_t r[32], s[32]; secp_ecdsa_sign(priv[i], sh, r, s);
            uint8_t der[80]; int dl = der_sig_e(der, r, s); emit_push(ss,&ssl,der,dl);
        }
        emit_push(ss,&ssl,rs,rl);
        uint8_t raw[600]; int rawl = e2e_rawtx(raw, ss, ssl);
        ATx t; if (tx_parse(raw, rawl, &t)) EMIT_E2E("e2e_multisig_valid", &t, 0);
        else { printf("e2e_multisig_valid PARSEFAIL\n"); }
    }
    #undef EMIT_E2E
    g_real_curve = 0;
}

// ── C-only self-checks (RIPEMD160 / DER / FindAndDelete KATs) ──────────────────
int attrib_selftest(void) {
    int fail = 0;
    uint8_t h[20];
    static const uint8_t kat_empty[20] = {0x9c,0x11,0x85,0xa5,0xc5,0xe9,0xfc,0x54,0x61,0x28,0x08,0x97,0x7e,0xe8,0xf5,0x48,0xb2,0x25,0x8d,0x31};
    static const uint8_t kat_abc[20]   = {0x8e,0xb2,0x08,0xf7,0xe0,0x5d,0x98,0x7a,0x9b,0x04,0x4a,0x8e,0x98,0xc6,0xb0,0x87,0xf1,0x5a,0x0b,0xfc};
    ripemd160((const uint8_t*)"", 0, h);       if (memcmp(h, kat_empty, 20)) { printf("FAIL: ripemd160(\"\")\n"); fail++; }
    ripemd160((const uint8_t*)"abc", 3, h);    if (memcmp(h, kat_abc, 20))   { printf("FAIL: ripemd160(\"abc\")\n"); fail++; }
    // hash160 of "abc"
    uint8_t hh[20]; hash160((const uint8_t*)"abc", 3, hh);
    static const uint8_t kat_h160_abc[20] = {0xbb,0x1b,0xe9,0x8c,0x14,0x24,0x44,0xd7,0xa5,0x6a,0xa3,0x98,0x1c,0x39,0x42,0xa9,0x78,0xe4,0xdc,0x33};
    if (memcmp(hh, kat_h160_abc, 20)) { printf("FAIL: hash160(\"abc\")\n"); fail++; }
    // FindAndDelete: remove a push of {0xAA,0xBB} (push = 02 AA BB) from a script
    { uint8_t s[] = {0x51, 0x02,0xAA,0xBB, 0x52, 0x02,0xAA,0xBB, 0xAE}; int sl = (int)sizeof s;
      uint8_t pat[] = {0x02,0xAA,0xBB};
      find_and_delete(s, &sl, pat, 3);
      uint8_t exp[] = {0x51, 0x52, 0xAE};
      if (sl != 3 || memcmp(s, exp, 3)) { printf("FAIL: find_and_delete basic\n"); fail++; } }
    // FindAndDelete must NOT remove a non-boundary match (pattern inside a push body)
    { uint8_t s[] = {0x04, 0x02,0xAA,0xBB,0xCC, 0xAE}; int sl = (int)sizeof s;  // a 4-byte push whose body contains 02 AA BB
      uint8_t pat[] = {0x02,0xAA,0xBB}; int before = sl;
      find_and_delete(s, &sl, pat, 3);
      if (sl != before) { printf("FAIL: find_and_delete boundary\n"); fail++; } }
    // DER: a valid minimal low-S sig round-trips; negative-S rejected
    { uint8_t sig[80]; int sl = 0; uint8_t R[32]={0}, S[32]={0}; R[0]=0x11; S[0]=0x22;
      put1(sig,&sl,0x30); put1(sig,&sl,0x44); put1(sig,&sl,0x02); put1(sig,&sl,0x20); put(sig,&sl,R,32);
      put1(sig,&sl,0x02); put1(sig,&sl,0x20); put(sig,&sl,S,32); put1(sig,&sl,0x01);
      uint8_t r32[32], s32[32];
      if (!der_parse(sig, sl, r32, s32)) { printf("FAIL: der_parse valid\n"); fail++; }
      sig[38] = 0x80;  // S[0] high bit → negative
      if (der_parse(sig, sl, r32, s32)) { printf("FAIL: der_parse should reject neg-S\n"); fail++; } }
    // secp256k1 real-curve KATs (constants, 2G, n·G=∞, decompress, sign/verify round-trip).
    int sf = secp_selftest();
    if (sf) { printf("FAIL: secp256k1 selftest (%d KAT failures)\n", sf); fail += sf; }
    if (!fail) printf("attrib selftest: ok (ripemd160 KAT, hash160, FindAndDelete, DER, secp256k1)\n");
    return fail;
}
