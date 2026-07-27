/* t_qr.c — the two image encoders/decoders the UI draws: the Receive card's QR
 * encoder (src/qr.c) and the Discover favicon decoder (src/favicon.c).
 *
 * Proves: qr_encode is a REAL QR Code encoder, not a plausible-looking bitmap.
 * The suite carries its own independent QR *decoder* (function-module map,
 * format-info BCH, zigzag codeword reader, GF(256) syndrome check, byte-mode
 * parser) written straight from ISO/IEC 18004 rather than from qr.c, and
 * round-trips every payload through it. Also pinned: the version ladder
 * (17/32/53/78 byte capacity → 21/25/29/33 modules), the exact ISO data
 * codeword stream for a hand-derived known answer, determinism, distinct
 * inputs → distinct symbols, both format-info copies agreeing, the dark
 * module, the alignment pattern, refusal (not silent truncation) of an
 * over-capacity payload, and no write past QR_MAX_SIZE^2 on a max-length
 * input.
 *
 * The second half covers src/favicon.c's decoder. That one matters for a
 * different reason: its input is a byte string ANY .pepe site can choose (the
 * Discover screen fetches /favicon.ico from every site it lists), so it is an
 * attacker-controlled parser running inside the wallet process. favicon.c is
 * #included because decode_rgba / decode_ico / decode_ico_dib are static; the
 * network fetch is stubbed out, so nothing here opens a socket.
 */
#include "qr.h"
#include "../src/favicon.c"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* favicon.c's only outward call — never reached, the suite feeds bytes direct */
size_t tls_loopback_get(uint16_t port, const char *sni, const char *path,
                        uint8_t **out, size_t cap) {
    (void)port; (void)sni; (void)path; (void)cap;
    *out = NULL;
    return 0;
}

static int g_fail;
#define CHECK(cond, name) do { \
    if (cond) printf("ok   %s\n", name); \
    else      { printf("FAIL %s\n", name); g_fail = 1; } \
} while (0)

/* ── SplitMix64: the suite's only randomness (never rand()) ───────────────── */
static unsigned long long g_rng = 0x9E3779B97F4A7C15ULL;
static unsigned long long sm64(void) {
    unsigned long long z = (g_rng += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* ── an independent QR decoder (ISO 18004, written from the spec) ─────────── */

/* GF(256) with the QR reduction polynomial 0x11D, by log/antilog tables —
 * deliberately a different implementation shape from qr.c's shift-and-xor. */
static unsigned char GF_EXP[512], GF_LOG[256];
static void gf_init(void) {
    int x = 1;
    for (int i = 0; i < 255; i++) {
        GF_EXP[i] = (unsigned char)x;
        GF_LOG[x] = (unsigned char)i;
        x <<= 1;
        if (x & 0x100) x ^= 0x11D;
    }
    for (int i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
}
static int gfmul(int a, int b) {
    if (!a || !b) return 0;
    return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

/* version → total / data codewords at ECC level L (ISO 18004 table 9) */
static const int T_TOTAL[5] = { 0, 26, 44, 70, 100 };
static const int T_DATA[5]  = { 0, 19, 34, 55, 80 };
static const int T_ALIGN[5] = { 0,  0, 18, 22, 26 };

static int ver_of_size(int n) { return (n - 17) / 4; }

/* the function-module map, derived from the spec's structure (not from qr.c):
 * the three 8x8 finder+separator corners plus their format strips, the two
 * timing lines, the dark module, and the single alignment pattern. */
static int is_function(int n, int ver, int x, int y) {
    if (x <= 8 && y <= 8) return 1;                 /* TL finder+sep+format */
    if (x >= n - 8 && y <= 8) return 1;             /* TR finder+sep+format */
    if (x <= 8 && y >= n - 8) return 1;             /* BL finder+sep+format+dark */
    if (x == 6 || y == 6) return 1;                 /* timing */
    int a = T_ALIGN[ver];
    if (a && x >= a - 2 && x <= a + 2 && y >= a - 2 && y <= a + 2) return 1;
    return 0;
}

static int mask_of(int m, int x, int y) {
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

/* the 15-bit BCH(15,5) format word for (ecl_bits, mask), pre-XORed with
 * 0x5412 — recomputed here from the spec generator 0x537 */
static int fmt_word(int ecl_bits, int mask) {
    int data = (ecl_bits << 3) | mask, rem = data;
    for (int i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    return ((data << 10) | rem) ^ 0x5412;
}

/* read format-info copy 1 (around the top-left finder) as a 15-bit word */
static int read_fmt1(const unsigned char *m, int n) {
    int b = 0;
    for (int i = 0; i <= 5; i++) b |= m[i * n + 8] << i;
    b |= m[7 * n + 8] << 6;
    b |= m[8 * n + 8] << 7;
    b |= m[8 * n + 7] << 8;
    for (int i = 9; i < 15; i++) b |= m[8 * n + (14 - i)] << i;
    return b;
}
/* read format-info copy 2 (split: bits 0..7 down the right edge of row 8,
 * bits 8..14 up the bottom of column 8) */
static int read_fmt2(const unsigned char *m, int n) {
    int b = 0;
    for (int i = 0; i < 8; i++)  b |= m[8 * n + (n - 1 - i)] << i;
    for (int i = 8; i < 15; i++) b |= m[(n - 15 + i) * n + 8] << i;
    return b;
}

/* zigzag codeword reader: column pairs right→left, alternating direction,
 * column 6 skipped (ISO 18004 §8.7.3) */
static int read_codewords(const unsigned char *m, int n, int ver, int mask,
                          unsigned char *cw, int ncw) {
    int i = 0, nbits = ncw * 8;
    memset(cw, 0, (size_t)ncw);
    for (int right = n - 1; right >= 1; right -= 2) {
        if (right == 6) right = 5;
        for (int vert = 0; vert < n; vert++)
            for (int j = 0; j < 2; j++) {
                int x = right - j;
                int up = ((right + 1) & 2) == 0;
                int y = up ? n - 1 - vert : vert;
                if (is_function(n, ver, x, y) || i >= nbits) continue;
                int bit = m[y * n + x] ^ mask_of(mask, x, y);
                cw[i >> 3] |= (unsigned char)(bit << (7 - (i & 7)));
                i++;
            }
    }
    return i;
}

/* Reed-Solomon syndromes: the generator's roots are a^0..a^(necc-1), so a
 * valid codeword evaluates to zero at each of them. */
static int rs_syndromes_zero(const unsigned char *cw, int ncw, int necc) {
    for (int s = 0; s < necc; s++) {
        int root = GF_EXP[s], acc = 0;
        for (int i = 0; i < ncw; i++) acc = gfmul(acc, root) ^ cw[i];
        if (acc) return 0;
    }
    return 1;
}

/* byte-mode segment parser; returns the payload length or -1 */
static int bp_get(const unsigned char *cw, int *bp, int nb) {
    int v = 0;
    for (int k = 0; k < nb; k++, (*bp)++)
        v = (v << 1) | ((cw[*bp >> 3] >> (7 - (*bp & 7))) & 1);
    return v;
}
static int parse_bytes(const unsigned char *cw, int ndata, char *out, int outcap) {
    int bp = 0;
    if (bp + 4 > ndata * 8) return -1;
    if (bp_get(cw, &bp, 4) != 4) return -1;         /* mode 0100 = byte */
    int len = bp_get(cw, &bp, 8);
    if (len < 1 || len >= outcap || (bp + len * 8) > ndata * 8) return -1;
    for (int i = 0; i < len; i++) out[i] = (char)bp_get(cw, &bp, 8);
    out[len] = 0;
    /* terminator: up to 4 zero bits, then pad to a byte boundary with zeros */
    int rem = ndata * 8 - bp, term = rem < 4 ? rem : 4;
    for (int i = 0; i < term; i++) if (bp_get(cw, &bp, 1) != 0) return -1;
    while (bp & 7) if (bp_get(cw, &bp, 1) != 0) return -1;
    /* pad codewords alternate 0xEC / 0x11 */
    for (int pad = 0xEC; bp < ndata * 8; pad ^= 0xEC ^ 0x11)
        if (bp_get(cw, &bp, 8) != pad) return -1;
    return len;
}

/* the whole decode: grid → text. rc 1 = decoded, *outlen filled. */
static int qr_decode(const unsigned char *m, int n, char *out, int outcap,
                     int *mask_out) {
    int ver = ver_of_size(n);
    if (ver < 1 || ver > 4 || 17 + 4 * ver != n) return 0;
    int f1 = read_fmt1(m, n), f2 = read_fmt2(m, n);
    if (f1 != f2) return 0;
    int ecl = -1, mask = -1;
    for (int e = 0; e < 4 && ecl < 0; e++)
        for (int k = 0; k < 8; k++)
            if (fmt_word(e, k) == f1) { ecl = e; mask = k; break; }
    if (ecl != 1) return 0;                          /* 0b01 = level L */
    if (mask_out) *mask_out = mask;
    int ndata = T_DATA[ver], necc = T_TOTAL[ver] - ndata;
    unsigned char cw[100];
    if (read_codewords(m, n, ver, mask, cw, ndata + necc) != (ndata + necc) * 8)
        return 0;
    if (!rs_syndromes_zero(cw, ndata + necc, necc)) return 0;
    return parse_bytes(cw, ndata, out, outcap) >= 0;
}

/* ── helpers ──────────────────────────────────────────────────────────────── */
static void fill_ascii(char *buf, int len) {
    for (int i = 0; i < len; i++) buf[i] = (char)('A' + (int)(sm64() % 26));
    buf[len] = 0;
}

int main(void) {
    gf_init();
    unsigned char mods[QR_MAX_SIZE * QR_MAX_SIZE + 64];
    int size = 0;

    printf("-- capacity ladder & refusal --\n");
    {
        /* the version ladder: byte capacity = data_cw - 2 at each version */
        struct { int len, want; } lad[] = {
            {  1, 21 }, { 17, 21 }, { 18, 25 }, { 32, 25 },
            { 33, 29 }, { 53, 29 }, { 54, 33 }, { 78, 33 },
        };
        char t[128];
        for (unsigned i = 0; i < sizeof lad / sizeof lad[0]; i++) {
            fill_ascii(t, lad[i].len);
            char nm[80];
            snprintf(nm, sizeof nm, "len %d -> %dx%d modules", lad[i].len, lad[i].want, lad[i].want);
            CHECK(qr_encode(t, mods, &size) == 1 && size == lad[i].want, nm);
        }
        CHECK(QR_MAX_TEXT == 78 && QR_MAX_SIZE == 33, "header pins v4/L capacity (78 bytes, 33 modules)");

        fill_ascii(t, 79);
        size = -1;
        CHECK(qr_encode(t, mods, &size) == 0, "79 bytes REFUSED (no silent truncation to v4)");
        CHECK(qr_encode("", mods, &size) == 0, "empty payload refused");
    }

    printf("-- no overrun on a max-length payload --\n");
    {
        char t[QR_MAX_TEXT + 1];
        fill_ascii(t, QR_MAX_TEXT);
        memset(mods, 0xA5, sizeof mods);
        CHECK(qr_encode(t, mods, &size) == 1 && size == 33, "78-byte payload encodes at v4");
        int clean = 1;
        for (unsigned i = QR_MAX_SIZE * QR_MAX_SIZE; i < sizeof mods; i++)
            if (mods[i] != 0xA5) clean = 0;
        CHECK(clean, "wrote nothing past QR_MAX_SIZE*QR_MAX_SIZE bytes");
        int only01 = 1;
        for (int i = 0; i < size * size; i++) if (mods[i] > 1) only01 = 0;
        CHECK(only01, "every module in the symbol is 0 or 1");
    }

    printf("-- known answer: the ISO data codeword stream for \"HELLO\" --\n");
    {
        /* Hand-derived from ISO 18004 §8.4.4 (byte mode, v1-L, 19 data cw):
         * 0100 | 00000101 | 'H''E''L''L''O' | 0000 term | pad EC/11 …        */
        static const unsigned char want[19] = {
            0x40, 0x54, 0x84, 0x54, 0xC4, 0xC4, 0xF0,
            0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11
        };
        CHECK(qr_encode("HELLO", mods, &size) == 1 && size == 21, "\"HELLO\" encodes at v1");
        int mask = -1;
        int ver = ver_of_size(size);
        int f1 = read_fmt1(mods, size);
        for (int e = 0; e < 4; e++)
            for (int k = 0; k < 8; k++)
                if (fmt_word(e, k) == f1 && e == 1) mask = k;
        CHECK(mask >= 0, "format info decodes to ECC level L");
        unsigned char cw[100];
        read_codewords(mods, size, ver, mask < 0 ? 0 : mask, cw, T_TOTAL[1]);
        CHECK(memcmp(cw, want, 19) == 0, "data codewords match the hand-derived ISO stream");
        CHECK(rs_syndromes_zero(cw, T_TOTAL[1], T_TOTAL[1] - T_DATA[1]),
              "Reed-Solomon parity verifies (all syndromes zero)");
    }

    printf("-- structural invariants --\n");
    {
        CHECK(qr_encode("pepenet", mods, &size) == 1, "encode a short payload");
        int n = size;
        /* three finders: 7x7 ring pattern dark/light/dark */
        int fin = 1;
        int cx[3] = { 3, n - 4, 3 }, cy[3] = { 3, 3, n - 4 };
        for (int f = 0; f < 3; f++)
            for (int dy = -3; dy <= 3; dy++)
                for (int dx = -3; dx <= 3; dx++) {
                    int ax = dx < 0 ? -dx : dx, ay = dy < 0 ? -dy : dy;
                    int ring = ax > ay ? ax : ay;
                    int want = ring != 2;
                    if (mods[(cy[f] + dy) * n + cx[f] + dx] != want) fin = 0;
                }
        CHECK(fin, "three 7x7 finder patterns are exact");
        /* separators: the light ring at Chebyshev 4 around each finder */
        int sep = 1;
        for (int f = 0; f < 3; f++)
            for (int dy = -4; dy <= 4; dy++)
                for (int dx = -4; dx <= 4; dx++) {
                    int ax = dx < 0 ? -dx : dx, ay = dy < 0 ? -dy : dy;
                    if ((ax > ay ? ax : ay) != 4) continue;
                    int x = cx[f] + dx, y = cy[f] + dy;
                    if (x < 0 || y < 0 || x >= n || y >= n) continue;
                    if (mods[y * n + x] != 0) sep = 0;
                }
        CHECK(sep, "finder separators are light on all three corners");
        /* timing patterns alternate, starting dark at index 6 */
        int tim = 1;
        for (int i = 8; i < n - 8; i++) {
            if (mods[6 * n + i] != (i % 2 == 0)) tim = 0;
            if (mods[i * n + 6] != (i % 2 == 0)) tim = 0;
        }
        CHECK(tim, "both timing patterns alternate correctly");
        CHECK(mods[(n - 8) * n + 8] == 1, "the mandatory dark module at (8, n-8) is set");
        CHECK(read_fmt1(mods, n) == read_fmt2(mods, n), "both format-info copies agree");
    }

    printf("-- alignment pattern (v2+) --\n");
    {
        char t[64];
        fill_ascii(t, 20);                          /* -> version 2, 25x25 */
        CHECK(qr_encode(t, mods, &size) == 1 && size == 25, "20 bytes -> v2");
        int n = size, a = T_ALIGN[2], ok = 1;
        for (int dy = -2; dy <= 2; dy++)
            for (int dx = -2; dx <= 2; dx++) {
                int ax = dx < 0 ? -dx : dx, ay = dy < 0 ? -dy : dy;
                int want = (ax > ay ? ax : ay) != 1;
                if (mods[(a + dy) * n + a + dx] != want) ok = 0;
            }
        CHECK(ok, "the single 5x5 alignment pattern is drawn at (18,18)");
        /* v1 has none: (18,18) does not exist there and nothing extra is drawn */
        CHECK(qr_encode("x", mods, &size) == 1 && size == 21, "v1 for a 1-byte payload");
    }

    printf("-- determinism & injectivity --\n");
    {
        unsigned char a[QR_MAX_SIZE * QR_MAX_SIZE], b[QR_MAX_SIZE * QR_MAX_SIZE];
        int sa = 0, sb = 0;
        CHECK(qr_encode("DQm1exampleaddress0000000000000000", a, &sa) == 1 &&
              qr_encode("DQm1exampleaddress0000000000000000", b, &sb) == 1 &&
              sa == sb && memcmp(a, b, (size_t)(sa * sa)) == 0,
              "same input -> byte-identical symbol");
        CHECK(qr_encode("DQm1exampleaddress0000000000000001", b, &sb) == 1 &&
              sa == sb && memcmp(a, b, (size_t)(sa * sa)) != 0,
              "one-character change -> a different symbol");
    }

    printf("-- round-trip: 4000 seeded-random payloads decode back --\n");
    {
        int bad_enc = 0, bad_dec = 0, bad_txt = 0, masks_seen = 0;
        char txt[QR_MAX_TEXT + 2], back[128];
        for (int it = 0; it < 4000; it++) {
            int len = 1 + (int)(sm64() % QR_MAX_TEXT);
            for (int i = 0; i < len; i++) {
                /* full printable-ASCII range, the alphabet an address/URI uses */
                txt[i] = (char)(0x21 + (int)(sm64() % 94));
            }
            txt[len] = 0;
            int sz = 0;
            if (qr_encode(txt, mods, &sz) != 1) { bad_enc++; continue; }
            int mask = -1;
            if (!qr_decode(mods, sz, back, sizeof back, &mask)) { bad_dec++; continue; }
            if (strcmp(back, txt) != 0) { bad_txt++; continue; }
            masks_seen |= 1 << mask;
        }
        CHECK(bad_enc == 0, "all 4000 in-capacity payloads encoded");
        CHECK(bad_dec == 0, "all 4000 symbols pass format BCH + RS syndromes");
        CHECK(bad_txt == 0, "all 4000 decode back to the exact input bytes");
        CHECK(masks_seen == 0xFF, "the mask trial actually selects all 8 masks across the corpus");
    }

    printf("-- round-trip: bytes with the high bit set (UTF-8 payloads) --\n");
    {
        int fails = 0;
        char txt[40], back[128];
        for (int it = 0; it < 500; it++) {
            int len = 1 + (int)(sm64() % 30);
            for (int i = 0; i < len; i++) txt[i] = (char)(0x80 | (int)(sm64() % 0x7F));
            txt[len] = 0;
            int sz = 0;
            if (qr_encode(txt, mods, &sz) != 1 ||
                !qr_decode(mods, sz, back, sizeof back, NULL) ||
                strcmp(back, txt) != 0) fails++;
        }
        CHECK(fails == 0, "500 high-bit payloads round-trip byte-exactly");
    }

    /* ══ src/favicon.c — the attacker-controlled image parser ═══════════════ */
    printf("-- favicon: a well-formed 32bpp .ico decodes to RGBA --\n");
    {
        /* ICONDIR(6) + ICONDIRENTRY(16) + BITMAPINFOHEADER(40) + 2x2 BGRA */
        unsigned char ico[6 + 16 + 40 + 16];
        memset(ico, 0, sizeof ico);
        ico[0] = 0; ico[1] = 0; ico[2] = 1; ico[3] = 0;      /* type 1 = icon */
        ico[4] = 1; ico[5] = 0;                              /* one entry */
        unsigned char *e = ico + 6;
        e[0] = 2; e[1] = 2;                                  /* 2x2 */
        unsigned len = 40 + 16, off = 6 + 16;
        e[8]  = (unsigned char)len;  e[9]  = (unsigned char)(len >> 8);
        e[12] = (unsigned char)off;  e[13] = (unsigned char)(off >> 8);
        unsigned char *bi = ico + off;
        bi[0] = 40;                                          /* biSize */
        bi[4] = 2;                                           /* biWidth  = 2 */
        bi[8] = 4;                                           /* biHeight = 4 (XOR+AND) */
        bi[12] = 1;                                          /* biPlanes */
        bi[14] = 32;                                         /* biBitCount */
        /* BGRA, bottom-up: row0 of the file is the BOTTOM row of the image */
        unsigned char *px = bi + 40;
        unsigned char rows[16] = {
            /* bottom row: pixels (0,1)=blue, (1,1)=white */
            0xFF,0x00,0x00,0xFF,  0xFF,0xFF,0xFF,0xFF,
            /* top row:    pixels (0,0)=red,  (1,0)=green */
            0x00,0x00,0xFF,0xFF,  0x00,0xFF,0x00,0xFF,
        };
        memcpy(px, rows, 16);

        int w = 0, h = 0;
        unsigned char *rgba = decode_rgba(ico, sizeof ico, &w, &h);
        CHECK(rgba != NULL, "a 2x2 32bpp .ico decodes");
        CHECK(w == 2 && h == 2, "…biHeight/2 is the real height (the AND mask is dropped)");
        if (rgba) {
            CHECK(rgba[0] == 0xFF && rgba[1] == 0x00 && rgba[2] == 0x00 && rgba[3] == 0xFF,
                  "…pixel (0,0) is red: BGRA became RGBA");
            CHECK(rgba[4] == 0x00 && rgba[5] == 0xFF && rgba[6] == 0x00,
                  "…pixel (1,0) is green");
            CHECK(rgba[8] == 0x00 && rgba[9] == 0x00 && rgba[10] == 0xFF,
                  "…pixel (0,1) is blue: the bottom-up DIB was flipped top-down");
            free(rgba);
        }
        /* the same DIB with no ICONDIR wrapper (the bare-.ico-body case) */
        w = h = 0;
        rgba = decode_rgba(bi, 40 + 16, &w, &h);
        CHECK(rgba != NULL && w == 2 && h == 2, "a BARE BITMAPINFOHEADER body decodes too");
        free(rgba);
    }

    printf("-- favicon: malformed images are refused, never guessed --\n");
    {
        int w = 0, h = 0;
        unsigned char ico[6 + 16 + 40 + 16];
        unsigned char tiny[4] = { 0, 0, 1, 0 };
        CHECK(decode_rgba(tiny, 4, &w, &h) == NULL, "an .ico header with no directory -> NULL");
        CHECK(decode_rgba((const unsigned char *)"", 0, &w, &h) == NULL, "an empty body -> NULL");

        memset(ico, 0, sizeof ico);
        ico[2] = 1; ico[4] = 0;                              /* count = 0 */
        CHECK(decode_rgba(ico, sizeof ico, &w, &h) == NULL, "an .ico with zero entries -> NULL");

        /* an entry whose data runs past the buffer */
        memset(ico, 0, sizeof ico);
        ico[2] = 1; ico[4] = 1;
        ico[6] = 2; ico[7] = 2;
        ico[6 + 8] = 0xFF; ico[6 + 9] = 0xFF;                /* len = 65535 */
        ico[6 + 12] = 22;                                    /* off = 22 */
        CHECK(decode_rgba(ico, sizeof ico, &w, &h) == NULL, "an entry running past the buffer -> NULL");

        /* a DIB the decoder must refuse: 24bpp, compressed, oversize, short */
        unsigned char bi[40 + 16];
        memset(bi, 0, sizeof bi);
        bi[0] = 40; bi[4] = 2; bi[8] = 4; bi[12] = 1; bi[14] = 24;
        CHECK(decode_rgba(bi, sizeof bi, &w, &h) == NULL, "a 24bpp DIB -> NULL (32bpp BI_RGB only)");
        bi[14] = 32; bi[16] = 3;                             /* biCompression = BI_BITFIELDS */
        CHECK(decode_rgba(bi, sizeof bi, &w, &h) == NULL, "a compressed DIB -> NULL");
        bi[16] = 0;
        bi[4] = 0; bi[5] = 4;                                /* biWidth = 1024 > FAV_DIM_CAP */
        CHECK(decode_rgba(bi, sizeof bi, &w, &h) == NULL, "a DIB wider than FAV_DIM_CAP -> NULL");
        bi[4] = 2; bi[5] = 0;
        bi[8] = 0; bi[9] = 4;                                /* biHeight = 1024 -> 512 rows */
        CHECK(decode_rgba(bi, sizeof bi, &w, &h) == NULL,
              "a DIB claiming 512 rows with 16 bytes of pixels -> NULL (short buffer)");
        bi[8] = 4; bi[9] = 0;
        bi[8] = 0xFE; bi[9] = 0xFF; bi[10] = 0xFF; bi[11] = 0xFF;   /* biHeight = -2 */
        CHECK(decode_rgba(bi, sizeof bi, &w, &h) == NULL, "a top-down (negative-height) DIB -> NULL");
        memset(bi, 0, sizeof bi);
        bi[0] = 39;                                          /* biSize < 40 */
        bi[14] = 32;
        CHECK(decode_rgba(bi, sizeof bi, &w, &h) == NULL, "a DIB with biSize < 40 -> NULL");
    }

    printf("-- favicon: 4000 seeded-random .ico bodies --\n");
    {
        int crashes = 0, oversize = 0, decoded = 0;
        unsigned char buf[512];
        for (int it = 0; it < 4000; it++) {
            int n = 4 + (int)(sm64() % (int)(sizeof buf - 4));
            for (int i = 0; i < n; i++) buf[i] = (unsigned char)sm64();
            /* half wear the .ico magic so the ico path is actually exercised */
            if (it & 1) { buf[0] = 0; buf[1] = 0; buf[2] = 1; buf[3] = 0; }
            int w = 0, h = 0;
            unsigned char *r = decode_rgba(buf, (size_t)n, &w, &h);
            if (r) {
                decoded++;
                if (w <= 0 || h <= 0 || w > FAV_DIM_CAP || h > FAV_DIM_CAP) oversize++;
                free(r);
            }
        }
        CHECK(crashes == 0, "4000 random bodies parsed without aborting");
        CHECK(oversize == 0, "every image the decoder DID accept is within FAV_DIM_CAP");
        (void)decoded;
    }

    printf("-- favicon: a self-referential .ico entry --\n");
    {
        /* An ICONDIRENTRY may point at offset 0 with length == the whole body.
         * decode_ico then calls decode_rgba on the IDENTICAL buffer, which
         * sees the .ico magic and calls decode_ico again — forever. Nothing in
         * the path carries a depth counter or shrinks the slice. Any .pepe
         * site can serve these 22 bytes as /favicon.ico and the Discover
         * screen fetches it unprompted.
         *
         * Run in a child so the suite survives the answer. */
        unsigned char loop[6 + 16];
        memset(loop, 0, sizeof loop);
        loop[2] = 1; loop[4] = 1;                            /* type 1, count 1 */
        loop[6] = 1; loop[7] = 1;                            /* 1x1 */
        loop[6 + 8] = (unsigned char)sizeof loop;            /* len = 22 */
        loop[6 + 12] = 0;                                    /* off = 0 -> itself */

        fflush(stdout);
        pid_t pid = fork();
        if (pid == 0) {
            alarm(3);                                        /* catch a TCO'd infinite LOOP too */
            int w = 0, h = 0;
            unsigned char *r = decode_rgba(loop, sizeof loop, &w, &h);
            free(r);
            _exit(0);
        }
        int status = 0;
        waitpid(pid, &status, 0);
        if (!WIFEXITED(status)) {
            int sig = WIFSIGNALED(status) ? WTERMSIG(status) : -1;
            printf("     decode_rgba never returned — child killed by signal %d (%s)\n", sig,
                   sig == SIGALRM ? "SIGALRM: it is spinning, the tail call became an infinite LOOP"
                                  : "stack exhausted by unbounded recursion");
        }
        CHECK(WIFEXITED(status),
              "FAILS: a self-referential .ico entry must terminate "
              "(decode_ico -> decode_rgba -> decode_ico, same slice, no depth bound)");
    }

    printf("-- favicon: the query API before boot --\n");
    {
        const unsigned char *rgba = NULL;
        int w = 0, h = 0;
        CHECK(favicon_query("alpha", &rgba, &w, &h) == FAV_NONE, "a query before boot is FAV_NONE");
        CHECK(favicon_query(NULL, &rgba, &w, &h) == FAV_NONE, "a NULL name is FAV_NONE");
        CHECK(favicon_query("", &rgba, &w, &h) == FAV_NONE, "an empty name is FAV_NONE");
        CHECK(rgba == NULL && w == 0 && h == 0, "…and nothing was written to the out params");
    }

    printf("%s\n", g_fail ? "t_qr: FAIL" : "t_qr: all ok");
    return g_fail;
}
