// qr.c — a complete QR Code encoder in ~300 lines, because the Receive card
// needs a scannable code and this app links no third-party source it can't
// read end to end.
//
// Scope (all we ever encode is a ~34-char address):
//   · byte mode only, ECC level L, versions 1–4 (17/32/53/78 byte capacity)
//   · versions 1–4 at level L are each a single Reed-Solomon block, so there
//     is no codeword interleaving to get wrong
//   · all 8 masks are tried with the four ISO 18004 §8.8.2 penalty rules and
//     the best kept (any mask decodes — the trial only optimizes readability)
// The structure mirrors the reference encoder everyone vendors (Nayuki's), so
// each step can be checked line-by-line against the spec section it encodes.

#include "qr.h"
#include <string.h>

// per version 1..4 at ECC L: total / data codewords, alignment center (k,k).
// v2+ define more alignment positions but every pair except (k,k) lands on a
// finder at these sizes, so exactly one pattern is drawn.
static const int TOTAL_CW[5]  = { 0, 26, 44, 70, 100 };
static const int DATA_CW[5]   = { 0, 19, 34, 55, 80 };
static const int ALIGN_POS[5] = { 0, 0, 18, 22, 26 };

// ── GF(256), reduction poly 0x11D — the QR Reed-Solomon field ────────────────
static int gf_mul(int x, int y) {
    int z = 0;
    for (int i = 7; i >= 0; i--) {
        z = (z << 1) ^ ((z >> 7) * 0x11D);
        z ^= ((y >> i) & 1) * x;
    }
    return z;
}

// generator polynomial (x−r^0)(x−r^1)…(x−r^(deg−1)), monic, low degree last
static void rs_divisor(int degree, unsigned char *out) {
    memset(out, 0, (size_t)degree);
    out[degree - 1] = 1;
    int root = 1;
    for (int i = 0; i < degree; i++) {
        for (int j = 0; j < degree; j++) {
            out[j] = (unsigned char)gf_mul(out[j], root);
            if (j + 1 < degree) out[j] ^= out[j + 1];
        }
        root = gf_mul(root, 0x02);
    }
}

static void rs_remainder(const unsigned char *data, int len,
                         const unsigned char *div, int degree,
                         unsigned char *out) {
    memset(out, 0, (size_t)degree);
    for (int i = 0; i < len; i++) {
        int factor = data[i] ^ out[0];
        memmove(out, out + 1, (size_t)(degree - 1));
        out[degree - 1] = 0;
        for (int j = 0; j < degree; j++)
            out[j] ^= (unsigned char)gf_mul(div[j], factor);
    }
}

// ── the module grid ──────────────────────────────────────────────────────────
typedef struct {
    int size;
    unsigned char mod[QR_MAX_SIZE * QR_MAX_SIZE];   // 1 = dark
    unsigned char fun[QR_MAX_SIZE * QR_MAX_SIZE];   // 1 = function module
} Grid;

static void set_fun(Grid *g, int x, int y, int dark) {
    g->mod[y * g->size + x] = (unsigned char)dark;
    g->fun[y * g->size + x] = 1;
}

// 7×7 finder + its light separator ring, clipped at the edges. By Chebyshev
// ring index from the center: 0,1 dark · 2 light · 3 dark · 4 light.
static void draw_finder(Grid *g, int cx, int cy) {
    for (int dy = -4; dy <= 4; dy++)
        for (int dx = -4; dx <= 4; dx++) {
            int x = cx + dx, y = cy + dy;
            if (x < 0 || y < 0 || x >= g->size || y >= g->size) continue;
            int ax = dx < 0 ? -dx : dx, ay = dy < 0 ? -dy : dy;
            int ring = ax > ay ? ax : ay;
            set_fun(g, x, y, ring != 2 && ring != 4);
        }
}

// 5×5 alignment: dark · light ring · dark center
static void draw_align(Grid *g, int cx, int cy) {
    for (int dy = -2; dy <= 2; dy++)
        for (int dx = -2; dx <= 2; dx++) {
            int ax = dx < 0 ? -dx : dx, ay = dy < 0 ? -dy : dy;
            int ring = ax > ay ? ax : ay;
            set_fun(g, cx + dx, cy + dy, ring != 1);
        }
}

// BCH(15,5)-protected format word for (ECC L, mask), pre-XORed per spec
static int format_bits(int mask) {
    int data = (1 << 3) | mask;                     // L = 0b01
    int rem = data;
    for (int i = 0; i < 10; i++)
        rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    return ((data << 10) | rem) ^ 0x5412;
}

static void draw_format(Grid *g, int mask) {
    int bits = format_bits(mask), n = g->size;
#define FB(i) (((bits) >> (i)) & 1)
    for (int i = 0; i <= 5; i++) set_fun(g, 8, i, FB(i));           // copy 1
    set_fun(g, 8, 7, FB(6));
    set_fun(g, 8, 8, FB(7));
    set_fun(g, 7, 8, FB(8));
    for (int i = 9; i < 15; i++) set_fun(g, 14 - i, 8, FB(i));
    for (int i = 0; i < 8; i++)  set_fun(g, n - 1 - i, 8, FB(i));   // copy 2
    for (int i = 8; i < 15; i++) set_fun(g, 8, n - 15 + i, FB(i));
    set_fun(g, 8, n - 8, 1);                                        // dark module
#undef FB
}

static void init_patterns(Grid *g, int ver) {
    int n = g->size;
    for (int i = 0; i < n; i++) {                   // timing, row & col 6
        set_fun(g, 6, i, i % 2 == 0);
        set_fun(g, i, 6, i % 2 == 0);
    }
    draw_finder(g, 3, 3);                           // finders overdraw timing ends
    draw_finder(g, n - 4, 3);
    draw_finder(g, 3, n - 4);
    if (ALIGN_POS[ver]) draw_align(g, ALIGN_POS[ver], ALIGN_POS[ver]);
    draw_format(g, 0);                              // reserves; redrawn per mask
}

// zigzag placement: column pairs right→left, alternating up/down, col 6 skipped;
// leftover modules (the v2–v4 remainder bits) stay light per spec
static void place_data(Grid *g, const unsigned char *cw, int ncw) {
    int n = g->size, i = 0, nbits = ncw * 8;
    for (int right = n - 1; right >= 1; right -= 2) {
        if (right == 6) right = 5;
        for (int vert = 0; vert < n; vert++)
            for (int j = 0; j < 2; j++) {
                int x = right - j;
                int up = ((right + 1) & 2) == 0;
                int y = up ? n - 1 - vert : vert;
                if (!g->fun[y * n + x] && i < nbits) {
                    g->mod[y * n + x] = (cw[i >> 3] >> (7 - (i & 7))) & 1;
                    i++;
                }
            }
    }
}

static int mask_bit(int m, int x, int y) {
    switch (m) {
    case 0:  return (x + y) % 2 == 0;
    case 1:  return y % 2 == 0;
    case 2:  return x % 3 == 0;
    case 3:  return (x + y) % 3 == 0;
    case 4:  return (x / 3 + y / 2) % 2 == 0;
    case 5:  return x * y % 2 + x * y % 3 == 0;
    case 6:  return (x * y % 2 + x * y % 3) % 2 == 0;
    default: return ((x + y) % 2 + x * y % 3) % 2 == 0;
    }
}

// XOR the mask over data modules only — calling twice is an exact undo
static void apply_mask(Grid *g, int m) {
    int n = g->size;
    for (int y = 0; y < n; y++)
        for (int x = 0; x < n; x++)
            if (!g->fun[y * n + x])
                g->mod[y * n + x] ^= (unsigned char)mask_bit(m, x, y);
}

// ISO 18004 §8.8.2 penalty — lower scans better
static int penalty(const Grid *g) {
    int n = g->size, score = 0;

    // rule 1: same-color runs ≥5 score 3+(run−5), both axes
    for (int y = 0; y < n; y++) {
        int runc = g->mod[y * n], run = 1;
        for (int x = 1; x <= n; x++) {
            int c = x < n ? g->mod[y * n + x] : -1;
            if (c == runc) run++;
            else { if (run >= 5) score += run - 2; runc = c; run = 1; }
        }
    }
    for (int x = 0; x < n; x++) {
        int runc = g->mod[x], run = 1;
        for (int y = 1; y <= n; y++) {
            int c = y < n ? g->mod[y * n + x] : -1;
            if (c == runc) run++;
            else { if (run >= 5) score += run - 2; runc = c; run = 1; }
        }
    }
    // rule 2: 2×2 blocks of one color
    for (int y = 0; y + 1 < n; y++)
        for (int x = 0; x + 1 < n; x++) {
            int c = g->mod[y * n + x];
            if (c == g->mod[y * n + x + 1] && c == g->mod[(y + 1) * n + x] &&
                c == g->mod[(y + 1) * n + x + 1]) score += 3;
        }
    // rule 3: finder lookalike — 1:1:3:1:1 dark runs flanked by 4 light
    static const unsigned char P1[11] = {0,0,0,0,1,0,1,1,1,0,1};
    static const unsigned char P2[11] = {1,0,1,1,1,0,1,0,0,0,0};
    for (int y = 0; y < n; y++)
        for (int x = 0; x + 11 <= n; x++) {
            int m1 = 1, m2 = 1;
            for (int k = 0; k < 11; k++) {
                int c = g->mod[y * n + x + k];
                m1 &= c == P1[k]; m2 &= c == P2[k];
            }
            score += (m1 + m2) * 40;
        }
    for (int x = 0; x < n; x++)
        for (int y = 0; y + 11 <= n; y++) {
            int m1 = 1, m2 = 1;
            for (int k = 0; k < 11; k++) {
                int c = g->mod[(y + k) * n + x];
                m1 &= c == P1[k]; m2 &= c == P2[k];
            }
            score += (m1 + m2) * 40;
        }
    // rule 4: 10 points per 5% the dark share sits away from 50%
    int dark = 0, total = n * n;
    for (int i = 0; i < total; i++) dark += g->mod[i];
    int dev = dark * 20 - total * 10;
    if (dev < 0) dev = -dev;
    return score + ((dev + total - 1) / total - 1) * 10;
}

int qr_encode(const char *text, unsigned char *mods, int *size) {
    int len = (int)strlen(text);
    if (len < 1 || len > QR_MAX_TEXT) return 0;

    int ver = 1;                                    // byte capacity = data_cw − 2
    while (DATA_CW[ver] - 2 < len) ver++;
    int ndata = DATA_CW[ver], necc = TOTAL_CW[ver] - ndata;

    // data codewords: mode 0100 · 8-bit count · bytes · terminator · pad
    unsigned char cw[100] = {0};
    int bp = 0;
#define PUT(v, nb) for (int b = (nb) - 1; b >= 0; b--, bp++) \
        cw[bp >> 3] |= (unsigned char)(((unsigned)(v) >> b & 1) << (7 - (bp & 7)))
    PUT(4, 4);
    PUT(len, 8);
    for (int i = 0; i < len; i++) PUT((unsigned char)text[i], 8);
    bp += 4; if (bp > ndata * 8) bp = ndata * 8;    // terminator (zeros pre-set)
    bp = (bp + 7) & ~7;
    for (int pad = 0xEC; bp < ndata * 8; pad ^= 0xEC ^ 0x11) PUT(pad, 8);
#undef PUT

    unsigned char divi[20], ecc[20];                // single block: ecc appends
    rs_divisor(necc, divi);
    rs_remainder(cw, ndata, divi, necc, ecc);
    memcpy(cw + ndata, ecc, (size_t)necc);

    Grid g;
    memset(&g, 0, sizeof g);
    g.size = 17 + ver * 4;
    init_patterns(&g, ver);
    place_data(&g, cw, ndata + necc);

    int bestm = 0, bests = 0x7fffffff;              // trial: mask+format, score, undo
    for (int m = 0; m < 8; m++) {
        apply_mask(&g, m);
        draw_format(&g, m);
        int s = penalty(&g);
        if (s < bests) { bests = s; bestm = m; }
        apply_mask(&g, m);
    }
    apply_mask(&g, bestm);
    draw_format(&g, bestm);

    for (int i = 0; i < g.size * g.size; i++) mods[i] = g.mod[i];
    *size = g.size;
    return 1;
}
