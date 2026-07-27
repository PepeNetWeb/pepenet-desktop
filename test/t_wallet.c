/* t_wallet.c — coin selection, change and the funding half of src/wallet.c.
 * This is the code that moves real money, so the suite drives the REAL path,
 * not a model of it: it stands up a throwaway SQLite projection under /tmp,
 * fills the utxos table the way the indexer would, and calls swl_run() with
 * dry_run=1. A whole transaction is funded, signed and put through wallet.c's
 * own pre-broadcast self-check (§4 attribution) — nothing touches the network,
 * nothing touches the macOS Keychain (platform_secret_* are stubbed to abort()
 * so a regression that reaches for it fails LOUDLY instead of prompting), and
 * no key material is ever printed or written: the signing key is a fixed
 * synthetic constant that guards no funds.
 *
 * Proves about SELECTION (src/wallet.c select_coins, and swl_tail around it):
 *   · a spent output is never selectable — a spent utxo big enough to fund the
 *     send does not fund it, and the send fails instead;
 *   · an outpoint the caller declares locked (an in-flight link already spends
 *     it) is never selected, and its value leaves the reported balance;
 *   · the selected set NEVER totals less than amount + fee: funded by exactly
 *     the right koinu succeeds, one koinu short fails, and failure is reported
 *     as SWL_R_ERR with no txid and no signed bytes — never an underfunded tx;
 *   · selection is minimal-prefix and its sum is exact, over 20000 random utxo
 *     sets INCLUDING sets built from values near 2^63.
 *
 * Proves about CHANGE — the koinu-conservation core:
 *   · inputs - amount - fee == change, checked twice: against what swl_run
 *     reports AND against the serialized transaction's own output values, so a
 *     koinu can be neither created nor lost between the two;
 *   · an exact-match input set produces NO change output (not a dust one);
 *   · change strictly below the 0.01 dust threshold is folded into the fee and
 *     the output disappears; change at exactly dust is kept;
 *   · want_change pads by one dust unit so a >= dust change output always
 *     exists, and reports insufficient funds rather than dropping the pad;
 *   · every accepted transaction satisfies sum(outputs) + actual_fee ==
 *     sum(inputs) with actual_fee in [requested_fee, requested_fee + dust).
 *
 * Proves the guards: amounts below dust, fees below the 0.001 relay floor,
 * negative fees, unknown coins and unknown ops are refused before any tx
 * exists; addresses are validated against the active coin's version byte and
 * survive NULL / empty / oversize / non-base58 / bad-checksum / embedded-NUL /
 * non-ASCII input without crashing.
 *
 * Two assertions below are marked FAILS: they assert the behaviour wallet.h
 * and wallet.c's own comments promise, and the code does not deliver it. They
 * are left asserting the CORRECT behaviour on purpose.
 */
#include "wallet.c"          /* select_coins / parse_amt / UtxoSet are static */
#include "fee.h"             /* the quote's floor must agree with the wallet's */

/* ── the seams this suite refuses to let the module reach ─────────────────
 * The OS keystore is off-limits: a test must never read, write or delete the
 * pepenet/wallet-pep Keychain item. wallet_boot() is the only caller and this
 * suite never invokes it — these stubs make that a hard guarantee. */
int platform_secret_get(const char *account, uint8_t *out, size_t cap) {
    (void)account; (void)out; (void)cap;
    fprintf(stderr, "FATAL: a test reached for the OS keystore\n");
    abort();
}
int platform_secret_set(const char *account, const uint8_t *secret, size_t len) {
    (void)account; (void)secret; (void)len;
    fprintf(stderr, "FATAL: a test reached for the OS keystore\n");
    abort();
}
/* the serve plane and the oracle feed are not part of the money math */
int  idx_serve_peer_held(const char *target) { (void)target; return 0; }
void oracle_record(OracleFeed *o, int64_t h, int64_t t, int64_t c, int64_t b) {
    (void)o; (void)h; (void)t; (void)c; (void)b;
}

static int g_fail, g_ok, g_nfail;
#define CHECK(cond, name) do { \
    if (cond) { printf("ok   %s\n", name); g_ok++; } \
    else      { printf("FAIL %s\n", name); g_fail = 1; g_nfail++; } \
} while (0)

/* deterministic PRNG — never rand(): a failing utxo set must be reproducible */
static uint64_t g_rng = 0xDEADBEEFCAFEF00DULL;
static uint64_t sm64(void) {
    uint64_t z = (g_rng += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* UBSan traps signed overflow; two probes below exist precisely to show the
 * product has no guard against it, so they are skipped under the sanitizer. */
#if defined(__has_feature)
#  if __has_feature(undefined_behavior_sanitizer)
#    define UBSAN_BUILD 1
#  endif
#endif
#ifndef UBSAN_BUILD
#  define UBSAN_BUILD 0
#endif

/* A synthetic signing key. It is not derived from any seed, it has never held
 * a coin, and it exists only so build_signed_tx has something to sign with. */
static const uint8_t TESTKEY[32] = {
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88, 0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x01,
    0x12,0x23,0x34,0x45,0x56,0x67,0x78,0x89, 0x9a,0xab,0xbc,0xcd,0xde,0xef,0xf0,0x02,
};

/* ══════════════ the throwaway projection ══════════════════════════════════ */
static char DBP[256];
static Wallet TW;                    /* the test wallet (h160 the utxos pay) */

static void db_open_fresh(void) {
    unlink(DBP);
    sqlite3 *db = idx_db_open(DBP);
    idx_db_close(db);
}
/* replace the whole utxo set; `spent` marks an output already consumed */
static void db_set_utxos(const int64_t *values, const int *spent, int n) {
    sqlite3 *db = idx_db_open(DBP);
    sqlite3_exec(db, "DELETE FROM utxos", NULL, NULL, NULL);
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "INSERT INTO utxos(txid,vout,h160,value,height,spent_height)"
                           " VALUES(?,?,?,?,?,?)", -1, &st, NULL);
    for (int i = 0; i < n; i++) {
        uint8_t txid[32];
        memset(txid, 0, 32);
        txid[0] = (uint8_t)(i + 1); txid[31] = (uint8_t)(i * 7 + 3);
        sqlite3_reset(st);
        sqlite3_bind_blob (st, 1, txid, 32, SQLITE_TRANSIENT);
        sqlite3_bind_int  (st, 2, i % 4);
        sqlite3_bind_blob (st, 3, TW.h160, 20, SQLITE_STATIC);
        sqlite3_bind_int64(st, 4, values[i]);
        sqlite3_bind_int64(st, 5, 1000 + i);
        if (spent && spent[i]) sqlite3_bind_int64(st, 6, 2000);
        else                   sqlite3_bind_null (st, 6);
        sqlite3_step(st);
    }
    sqlite3_finalize(st);
    idx_db_close(db);
}

/* ── a byte-level view of the built transaction ─────────────────────────── */
typedef struct { int nin, nout; int64_t vals[16], out_total; } TxView;
static uint64_t rdvar(const uint8_t *b, size_t *p) {
    uint8_t v = b[(*p)++];
    if (v < 0xFD) return v;
    if (v == 0xFD) { uint64_t r = (uint64_t)b[*p] | ((uint64_t)b[*p+1] << 8); *p += 2; return r; }
    return 0;      /* wallet.c's putvar never emits FE/FF */
}
static int tx_parse(const uint8_t *tx, size_t len, TxView *v) {
    memset(v, 0, sizeof *v);
    size_t p = 4;                                        /* version */
    if (len < 10) return 0;
    v->nin = (int)rdvar(tx, &p);
    for (int i = 0; i < v->nin; i++) {
        p += 36;
        uint64_t sl = rdvar(tx, &p);
        p += (size_t)sl + 4;
        if (p > len) return 0;
    }
    v->nout = (int)rdvar(tx, &p);
    if (v->nout > 16) return 0;
    for (int i = 0; i < v->nout; i++) {
        uint64_t val = 0;
        for (int k = 0; k < 8; k++) val |= (uint64_t)tx[p + k] << (8 * k);
        p += 8;
        v->vals[i] = (int64_t)val;
        v->out_total += (int64_t)val;
        uint64_t sl = rdvar(tx, &p);
        p += (size_t)sl;
        if (p > len) return 0;
    }
    return p + 4 == len;
}

/* ── one send through the real engine ───────────────────────────────────── */
static int send_req(int64_t amount, int64_t fee, int want_change, int sweep,
                    const SwlOutpoint *locked, int nlocked,
                    const SwlSpendable *virt, int nvirt, SwlRes *res) {
    SwlReq r;
    memset(&r, 0, sizeof r);
    r.op = SWL_SEND;
    r.dbpath = DBP;
    r.dry_run = 1;                       /* build + sign + self-check, no socket */
    r.fee = fee;
    r.amount = amount;
    r.want_change = want_change;
    r.sweep = sweep;
    r.locked = locked; r.nlocked = nlocked;
    r.virt = virt;     r.nvirt = nvirt;
    memset(r.to160, 0x77, 20);
    memcpy(r.key.seckey, TESTKEY, 32);
    snprintf(r.key.coin, sizeof r.key.coin, "pep");
    return swl_run(&r, res);
}
static int send_simple(int64_t amount, int64_t fee, SwlRes *res) {
    return send_req(amount, fee, 0, 0, NULL, 0, NULL, 0, res);
}

/* every invariant a built transaction must satisfy, in one place */
static int conserves(const SwlRes *res, int64_t amount, int64_t req_fee, char *why, size_t cap) {
    TxView v;
    if (!tx_parse(res->raw, res->rawlen, &v)) { snprintf(why, cap, "tx did not parse"); return 0; }
    if (v.nin != res->nins) { snprintf(why, cap, "tx has %d inputs, res says %d", v.nin, res->nins); return 0; }
    if (res->spent_inputs < amount + req_fee) { snprintf(why, cap, "selected below amount+fee"); return 0; }
    if (v.vals[0] != amount) { snprintf(why, cap, "recipient output != amount"); return 0; }
    if (v.out_total != amount + res->change) { snprintf(why, cap, "outputs != amount+change"); return 0; }
    int64_t actual_fee = res->spent_inputs - v.out_total;
    if (actual_fee < req_fee) { snprintf(why, cap, "actual fee below the requested fee"); return 0; }
    if (actual_fee >= req_fee + DUST) { snprintf(why, cap, "fee absorbed a dust unit or more"); return 0; }
    if (res->change > 0) {
        if (actual_fee != req_fee) { snprintf(why, cap, "change kept but fee moved"); return 0; }
        if (res->change < DUST) { snprintf(why, cap, "sub-dust change output emitted"); return 0; }
        if (!res->has_change || v.nout != 2) { snprintf(why, cap, "change flagged wrong"); return 0; }
        if (v.vals[res->change_vout] != res->change) { snprintf(why, cap, "change_vout value wrong"); return 0; }
    } else if (res->has_change || v.nout != 1) {
        snprintf(why, cap, "zero change but a change output exists");
        return 0;
    }
    /* the exact conservation identity */
    if (res->spent_inputs != amount + res->change + actual_fee) {
        snprintf(why, cap, "inputs != amount + change + fee");
        return 0;
    }
    return 1;
}

int main(void) {
    char why[128], name[160];
    snprintf(DBP, sizeof DBP, "/tmp/t_wallet_%d.db", (int)getpid());

    memset(&TW, 0, sizeof TW);
    TW.coin = wcoin("pep");
    memcpy(TW.seckey, TESTKEY, 32);
    if (!TW.coin || !wallet_derive(&TW)) { printf("FAIL test wallet would not derive\n"); return 1; }
    db_open_fresh();

    /* ═══ 1. the constants the money math is pinned to ══════════════════ */
    printf("-- pinned money constants --\n");
    CHECK(COIN_UNIT == 100000000LL, "COIN_UNIT is 1e8 koinu");
    CHECK(DUST == 1000000LL,        "DUST is 0.01 (Dogecoin-1.14 threshold)");
    CHECK(FEE_MIN == 100000LL,      "FEE_MIN is the 0.001 relay floor");
    CHECK(FEE_MIN == FEE_FLOOR_K,   "wallet's FEE_MIN agrees with fee.h's FEE_FLOOR_K");
    CHECK(MAX_INS == SWL_MAX_INS && MAX_INS == 16, "MAX_INS is 16 and wallet.h mirrors it");
    CHECK(DUST > FEE_MIN,           "the dust threshold is above the relay floor");

    /* ═══ 2. select_coins: unit contract ════════════════════════════════ */
    printf("-- select_coins contract --\n");
    {
        UtxoSet s; int64_t sum; int n;

        memset(&s, 0, sizeof s);
        n = select_coins(&s, COIN_UNIT, &sum);
        CHECK(n == 0 && sum == 0, "empty set cannot fund anything");

        s.n = 3;
        s.u[0].value = 5 * COIN_UNIT; s.u[1].value = 3 * COIN_UNIT; s.u[2].value = COIN_UNIT;
        s.total = 9 * COIN_UNIT;

        n = select_coins(&s, 4 * COIN_UNIT, &sum);
        CHECK(n == 1 && sum == 5 * COIN_UNIT, "one input suffices → exactly one selected");
        n = select_coins(&s, 5 * COIN_UNIT, &sum);
        CHECK(n == 1 && sum == 5 * COIN_UNIT, "need == first input → still one input");
        n = select_coins(&s, 5 * COIN_UNIT + 1, &sum);
        CHECK(n == 2 && sum == 8 * COIN_UNIT, "one koinu more takes a second input");
        n = select_coins(&s, 9 * COIN_UNIT, &sum);
        CHECK(n == 3 && sum == 9 * COIN_UNIT, "the whole set funds its own total exactly");
        n = select_coins(&s, 9 * COIN_UNIT + 1, &sum);
        CHECK(n == 0, "one koinu past the total is refused, not part-funded");
        CHECK(sum == 9 * COIN_UNIT, "*in_sum is still written on refusal");

        /* the input cap */
        memset(&s, 0, sizeof s);
        s.n = 20;
        for (int i = 0; i < 20; i++) { s.u[i].value = COIN_UNIT; s.total += COIN_UNIT; }
        n = select_coins(&s, 16 * COIN_UNIT, &sum);
        CHECK(n == MAX_INS && sum == 16 * COIN_UNIT, "16 one-coin inputs are selectable");
        n = select_coins(&s, 17 * COIN_UNIT, &sum);
        CHECK(n == 0, "the 17th coin is out of reach: MAX_INS caps selection");

        /* zero-value outputs are still counted as inputs */
        memset(&s, 0, sizeof s);
        s.n = 3;
        s.u[0].value = 0; s.u[1].value = 0; s.u[2].value = COIN_UNIT;
        n = select_coins(&s, COIN_UNIT, &sum);
        CHECK(n == 3 && sum == COIN_UNIT, "zero-value utxos are consumed before a funding one");
    }

    /* ═══ 3. select_coins: property, 20000 random sets ══════════════════ */
    printf("-- select_coins property (20000 random utxo sets) --\n");
    {
        int bad_sum = 0, bad_min = 0, bad_short = 0, bad_range = 0, bad_refuse = 0;
        for (int t = 0; t < 20000; t++) {
            UtxoSet s;
            memset(&s, 0, sizeof s);
            s.n = (int)(sm64() % 40);
            for (int i = 0; i < s.n; i++) {
                uint64_t r = sm64();
                switch (t % 4) {
                case 0:  s.u[i].value = (int64_t)(r % (uint64_t)(10 * COIN_UNIT)); break;
                case 1:  s.u[i].value = (int64_t)(r % 1000) + 1; break;
                case 2:  s.u[i].value = (int64_t)(r % (uint64_t)COIN_UNIT) * 1000; break;
                default: s.u[i].value = (int64_t)(r % 5) * COIN_UNIT; break;
                }
                s.total += s.u[i].value;
            }
            int64_t need = (int64_t)(sm64() % (uint64_t)(s.total + 3 * COIN_UNIT + 1)) + 1;
            int64_t sum = -1;
            int n = select_coins(&s, need, &sum);

            if (n < 0 || n > MAX_INS || n > s.n) { bad_range++; continue; }
            /* *in_sum is the sum of the first n, always */
            int64_t chk = 0;
            for (int i = 0; i < n; i++) chk += s.u[i].value;
            if (n && sum != chk) bad_sum++;

            if (n) {
                if (sum < need) bad_short++;                       /* never underfund */
                /* minimal prefix: dropping the last input drops below need */
                if (n > 1 && chk - s.u[n-1].value >= need) bad_min++;
            } else {
                /* refusal is only correct when no prefix of <= MAX_INS reaches need */
                int64_t best = 0;
                int lim = s.n < MAX_INS ? s.n : MAX_INS;
                for (int i = 0; i < lim; i++) best += s.u[i].value;
                if (best >= need) bad_refuse++;
            }
        }
        CHECK(bad_range == 0,  "the input count is always in [0, min(set, MAX_INS)]");
        CHECK(bad_sum == 0,    "*in_sum is exactly the sum of the selected prefix");
        CHECK(bad_short == 0,  "a funded selection NEVER totals below the target");
        CHECK(bad_min == 0,    "the selection is minimal: the last input is load-bearing");
        CHECK(bad_refuse == 0, "refusal happens only when no reachable prefix covers the target");
    }

    /* near-2^63: the accumulator has no overflow guard (wallet.c:406) */
    printf("-- select_coins at the 64-bit boundary --\n");
    {
        UtxoSet s; int64_t sum;
        memset(&s, 0, sizeof s);
        s.n = 2;
        s.u[0].value = INT64_MAX / 2;
        s.u[1].value = INT64_MAX - INT64_MAX / 2;              /* sums to exactly 2^63-1 */
        s.total = INT64_MAX;
        int n = select_coins(&s, INT64_MAX, &sum);
        CHECK(n == 2 && sum == INT64_MAX, "a set summing to exactly INT64_MAX funds INT64_MAX");
        n = select_coins(&s, INT64_MAX / 2, &sum);
        CHECK(n == 1 && sum == INT64_MAX / 2, "the boundary set still stops at the first input");

        memset(&s, 0, sizeof s);
        s.n = 3;
        for (int i = 0; i < 3; i++) s.u[i].value = INT64_MAX / 2;
#if UBSAN_BUILD
        printf("skip select_coins overflow probe (UBSan build traps the wrap)\n");
#else
        /* FAILS (see report): the accumulator at wallet.c:406 is a bare
         * `*in_sum += value` with no overflow guard, so a third near-2^62
         * output wraps it NEGATIVE (signed overflow — UB, and UBSan traps it).
         * Whatever the funding verdict, a running total of selected koinu must
         * never be reported as a negative number. */
        sum = 0;
        n = select_coins(&s, INT64_MAX, &sum);
        CHECK(sum >= 0, "the selected-input total never wraps negative (3 x 2^62 koinu)");
        (void)n;
#endif
    }

    /* ═══ 4. the real funding path: change conservation ═════════════════ */
    printf("-- swl_run(SWL_SEND, dry_run): change conservation --\n");
    {
        SwlRes res;
        int64_t v3[3] = { 5 * COIN_UNIT, 3 * COIN_UNIT, COIN_UNIT };
        db_set_utxos(v3, NULL, 3);

        CHECK(send_simple(2 * COIN_UNIT, FEE_DEFAULT, &res) == 1 && res.code == SWL_R_OK,
              "a funded send builds and self-checks");
        CHECK(res.nins == 1 && res.spent_inputs == 5 * COIN_UNIT,
              "the db's value-DESC order makes selection largest-first");
        CHECK(res.change == 5 * COIN_UNIT - 2 * COIN_UNIT - FEE_DEFAULT,
              "change == inputs - amount - fee, exactly");
        CHECK(conserves(&res, 2 * COIN_UNIT, FEE_DEFAULT, why, sizeof why), "conservation holds");
        if (!conserves(&res, 2 * COIN_UNIT, FEE_DEFAULT, why, sizeof why)) printf("     (%s)\n", why);
        CHECK(res.rawlen > 0 && res.txid[0] && res.dry == 1 && res.accepted == 0,
              "the signed bytes are kept, a txid is reported, nothing was sent");

        CHECK(send_simple(7 * COIN_UNIT, FEE_DEFAULT, &res) == 1 && res.nins == 2 &&
              res.spent_inputs == 8 * COIN_UNIT &&
              res.change == 8 * COIN_UNIT - 7 * COIN_UNIT - FEE_DEFAULT,
              "a two-input send conserves koinu the same way");
        CHECK(conserves(&res, 7 * COIN_UNIT, FEE_DEFAULT, why, sizeof why),
              "two-input conservation holds");

        /* every input the tx spends is reported back for the queue's link */
        int ins_ok = (res.nins == 2 && res.has_change &&
                      !memcmp(res.in0_txid, res.ins[0].txid, 32) &&
                      res.in0_vout == res.ins[0].vout);
        CHECK(ins_ok, "res.ins[] and in0 name the outpoints the tx actually spends");
    }

    /* exact match: no change output at all */
    printf("-- exact match and the dust fold --\n");
    {
        SwlRes res;
        int64_t exact[1] = { 2 * COIN_UNIT + FEE_DEFAULT };
        db_set_utxos(exact, NULL, 1);
        CHECK(send_simple(2 * COIN_UNIT, FEE_DEFAULT, &res) == 1 && res.code == SWL_R_OK &&
              res.change == 0 && res.has_change == 0,
              "an exact-match input set produces NO change");
        TxView v;
        CHECK(tx_parse(res.raw, res.rawlen, &v) && v.nout == 1 && v.vals[0] == 2 * COIN_UNIT,
              "the exact-match tx carries exactly one output, the payment");
        CHECK(conserves(&res, 2 * COIN_UNIT, FEE_DEFAULT, why, sizeof why),
              "exact-match conservation holds");

        /* one koinu of change: strictly sub-dust, must be folded into the fee */
        int64_t one[1] = { 2 * COIN_UNIT + FEE_DEFAULT + 1 };
        db_set_utxos(one, NULL, 1);
        CHECK(send_simple(2 * COIN_UNIT, FEE_DEFAULT, &res) == 1 && res.change == 0 &&
              res.has_change == 0,
              "1 koinu of change is folded into the fee, no output");
        CHECK(tx_parse(res.raw, res.rawlen, &v) && v.nout == 1 &&
              res.spent_inputs - v.out_total == FEE_DEFAULT + 1,
              "the folded koinu shows up in the fee, not lost");

        /* DUST-1: still folded */
        int64_t just_under[1] = { 2 * COIN_UNIT + FEE_DEFAULT + DUST - 1 };
        db_set_utxos(just_under, NULL, 1);
        CHECK(send_simple(2 * COIN_UNIT, FEE_DEFAULT, &res) == 1 && res.change == 0 &&
              res.spent_inputs - 2 * COIN_UNIT == FEE_DEFAULT + DUST - 1,
              "change of DUST-1 is folded into the fee");

        /* exactly DUST: kept as a real output */
        int64_t at_dust[1] = { 2 * COIN_UNIT + FEE_DEFAULT + DUST };
        db_set_utxos(at_dust, NULL, 1);
        CHECK(send_simple(2 * COIN_UNIT, FEE_DEFAULT, &res) == 1 && res.change == DUST &&
              res.has_change == 1,
              "change of exactly DUST is kept as an output");
        CHECK(conserves(&res, 2 * COIN_UNIT, FEE_DEFAULT, why, sizeof why),
              "at-dust conservation holds");
    }

    /* ═══ 5. insufficient funds is a refusal, never a short tx ══════════ */
    printf("-- insufficient funds --\n");
    {
        SwlRes res;
        int64_t v[1] = { 2 * COIN_UNIT + FEE_DEFAULT - 1 };     /* one koinu short */
        db_set_utxos(v, NULL, 1);
        int ok = send_simple(2 * COIN_UNIT, FEE_DEFAULT, &res);
        CHECK(ok == 0 && res.code == SWL_R_ERR, "one koinu short is refused");
        CHECK(res.rawlen == 0 && res.txid[0] == 0 && res.nins == 0 && res.spent_inputs == 0,
              "a refusal leaves no signed bytes, no txid, no inputs");
        CHECK(res.net_fail == 0 && strstr(res.err, "insufficient") != NULL,
              "the refusal is a guard refusal, not a network failure");

        v[0] = 2 * COIN_UNIT + FEE_DEFAULT;                      /* exactly enough */
        db_set_utxos(v, NULL, 1);
        CHECK(send_simple(2 * COIN_UNIT, FEE_DEFAULT, &res) == 1,
              "exactly enough succeeds (the boundary is inclusive)");

        int64_t none[1] = { 0 };
        db_set_utxos(none, NULL, 0);
        CHECK(send_simple(DUST, FEE_MIN, &res) == 0 && res.code == SWL_R_ERR,
              "an empty wallet refuses even a dust payment");
    }

    /* ═══ 6. spent and locked outputs are never selectable ══════════════ */
    printf("-- spent and locked outputs --\n");
    {
        SwlRes res;
        /* a spent 100-coin output next to 1 coin of real balance */
        int64_t v[2]   = { 100 * COIN_UNIT, COIN_UNIT };
        int     sp[2]  = { 1, 0 };
        db_set_utxos(v, sp, 2);
        CHECK(send_simple(50 * COIN_UNIT, FEE_DEFAULT, &res) == 0 && res.code == SWL_R_ERR,
              "a SPENT output cannot fund a send, however large it is");
        CHECK(send_simple(DUST, FEE_DEFAULT, &res) == 1 && res.spent_inputs == COIN_UNIT,
              "only the unspent output funds the send");

        /* the same, via the queue's locked list */
        int64_t v2[2] = { 100 * COIN_UNIT, COIN_UNIT };
        db_set_utxos(v2, NULL, 2);
        SwlOutpoint lock;
        memset(lock.txid, 0, 32);
        lock.txid[0] = 1; lock.txid[31] = 3;                     /* utxo 0's synthetic txid */
        lock.vout = 0;
        CHECK(send_req(50 * COIN_UNIT, FEE_DEFAULT, 0, 0, &lock, 1, NULL, 0, &res) == 0 &&
              res.code == SWL_R_ERR,
              "a LOCKED outpoint (in-flight link) cannot fund a send");
        CHECK(send_req(DUST, FEE_DEFAULT, 0, 0, &lock, 1, NULL, 0, &res) == 1 &&
              res.spent_inputs == COIN_UNIT,
              "the locked outpoint is skipped and the next one funds");
        CHECK(send_req(50 * COIN_UNIT, FEE_DEFAULT, 0, 0, NULL, 0, NULL, 0, &res) == 1,
              "unlocked again, the same output funds the same send");
    }

    /* in-flight change is front-loaded so the queue chains off the newest link */
    printf("-- in-flight (virtual) change --\n");
    {
        SwlRes res;
        int64_t v[1] = { 100 * COIN_UNIT };
        db_set_utxos(v, NULL, 1);
        SwlSpendable virt;
        memset(virt.txid, 0xEE, 32);
        virt.vout = 1;
        virt.value = 4 * COIN_UNIT;
        CHECK(send_req(COIN_UNIT, FEE_DEFAULT, 0, 0, NULL, 0, &virt, 1, &res) == 1 &&
              res.nins == 1 && res.spent_inputs == 4 * COIN_UNIT &&
              !memcmp(res.in0_txid, virt.txid, 32) && res.in0_vout == 1,
              "an in-flight output is selected FIRST, ahead of a larger confirmed one");
        CHECK(conserves(&res, COIN_UNIT, FEE_DEFAULT, why, sizeof why),
              "chaining off in-flight change still conserves koinu");
    }

    /* ═══ 7. want_change ════════════════════════════════════════════════ */
    printf("-- want_change (the queue's mandatory change output) --\n");
    {
        SwlRes res;
        int64_t exact[1] = { 2 * COIN_UNIT + FEE_DEFAULT };
        db_set_utxos(exact, NULL, 1);
        CHECK(send_req(2 * COIN_UNIT, FEE_DEFAULT, 1, 0, NULL, 0, NULL, 0, &res) == 0 &&
              res.code == SWL_R_ERR && strstr(res.err, "change buffer") != NULL,
              "want_change refuses rather than dropping the mandatory change output");

        int64_t plenty[1] = { 2 * COIN_UNIT + FEE_DEFAULT + DUST };
        db_set_utxos(plenty, NULL, 1);
        CHECK(send_req(2 * COIN_UNIT, FEE_DEFAULT, 1, 0, NULL, 0, NULL, 0, &res) == 1 &&
              res.has_change == 1 && res.change >= DUST,
              "want_change with the pad available yields a >= dust change output");
        CHECK(conserves(&res, 2 * COIN_UNIT, FEE_DEFAULT, why, sizeof why),
              "want_change conservation holds");
    }

    /* ═══ 8. the guards ═════════════════════════════════════════════════ */
    printf("-- pre-tx guards --\n");
    {
        SwlRes res;
        int64_t v[1] = { 100 * COIN_UNIT };
        db_set_utxos(v, NULL, 1);

        CHECK(send_simple(DUST - 1, FEE_DEFAULT, &res) == 0 && res.code == SWL_R_ERR &&
              strstr(res.err, "dust") != NULL, "an amount below dust is refused");
        CHECK(send_simple(0, FEE_DEFAULT, &res) == 0, "a zero-amount send is refused");
        CHECK(send_simple(-COIN_UNIT, FEE_DEFAULT, &res) == 0, "a negative amount is refused");
        CHECK(send_simple(COIN_UNIT, FEE_MIN - 1, &res) == 0 && res.code == SWL_R_ERR &&
              strstr(res.err, "relay floor") != NULL, "a fee below the relay floor is refused");
        CHECK(send_simple(COIN_UNIT, 0, &res) == 0, "a zero fee is refused");
        CHECK(send_simple(COIN_UNIT, INT64_MIN, &res) == 0, "a hugely negative fee is refused");
        CHECK(send_simple(COIN_UNIT, FEE_MIN, &res) == 1, "the relay floor itself is accepted");

        /* unknown coin / unknown op never reach the funding path */
        SwlReq r;
        memset(&r, 0, sizeof r);
        r.op = SWL_SEND; r.dbpath = DBP; r.dry_run = 1; r.fee = FEE_DEFAULT;
        r.amount = COIN_UNIT; memcpy(r.key.seckey, TESTKEY, 32);
        snprintf(r.key.coin, sizeof r.key.coin, "notacoin");
        CHECK(swl_run(&r, &res) == 0 && strstr(res.err, "unknown coin") != NULL,
              "an unknown coin is refused before any tx exists");
        r.key.coin[0] = 0;
        CHECK(swl_run(&r, &res) == 0, "an empty coin name is refused");
        snprintf(r.key.coin, sizeof r.key.coin, "pep");
        r.op = (SwlOp)999;
        CHECK(swl_run(&r, &res) == 0 && strstr(res.err, "unknown wallet op") != NULL,
              "an out-of-range op is refused");
        r.op = SWL_SEND;
        memset(r.key.seckey, 0, 32);                    /* the zero scalar is not a key */
        CHECK(swl_run(&r, &res) == 0 && strstr(res.err, "secret key") != NULL,
              "an all-zero secret key is refused");
        memset(r.key.seckey, 0xFF, 32);                 /* above the curve order */
        CHECK(swl_run(&r, &res) == 0, "a secret key above the group order is refused");

        /* a missing / unreadable db is a refusal, not a crash */
        memcpy(r.key.seckey, TESTKEY, 32);
        r.dbpath = "/nonexistent-dir-xyz/none.db";
        CHECK(swl_run(&r, &res) == 0 && res.code == SWL_R_ERR,
              "an unopenable chain db is refused cleanly");
    }

    /* ═══ 9. the MAX_INS cap, and what the user is told about it ════════ */
    printf("-- the 16-input cap --\n");
    {
        SwlRes res;
        int64_t v[20];
        for (int i = 0; i < 20; i++) v[i] = COIN_UNIT;
        db_set_utxos(v, NULL, 20);

        CHECK(send_simple(15 * COIN_UNIT, FEE_DEFAULT, &res) == 1 && res.nins == MAX_INS,
              "a send needing 16 inputs builds");
        CHECK(conserves(&res, 15 * COIN_UNIT, FEE_DEFAULT, why, sizeof why),
              "a 16-input tx conserves koinu");

        int ok = send_simple(18 * COIN_UNIT, FEE_DEFAULT, &res);
        CHECK(ok == 0 && res.code == SWL_R_ERR,
              "a send needing 17+ inputs is refused (MAX_INS), not silently short-funded");
        /* FAILS (see report): the refusal text is built from s.total, the WHOLE
         * spendable balance, so it reads "need 18.1, have 20.0" — it tells the
         * user they have enough for a send that was just refused. The honest
         * report is the reachable total (16 inputs = 16.0). */
        CHECK(strstr(res.err, "have 16.") != NULL,
              "the refusal reports the REACHABLE balance, not one that contradicts it");
    }

    /* ═══ 10. sweep — wallet.h's contract vs the code ═══════════════════ */
    printf("-- sweep (SwlReq.sweep) --\n");
    {
        SwlRes res;
        int64_t v[3] = { 5 * COIN_UNIT, 3 * COIN_UNIT, COIN_UNIT };
        db_set_utxos(v, NULL, 3);

        /* the "max" button (ui/view_screens.c:779 → ops_send(.., sweep=1)) sets
         * amount = balance - fee, and THAT case works today by arithmetic
         * accident: need == the whole balance, so every input is selected and
         * the change is zero without anyone consulting the flag. */
        CHECK(send_req(9 * COIN_UNIT - FEE_DEFAULT, FEE_DEFAULT, 0, 1, NULL, 0, NULL, 0, &res) == 1 &&
              res.nins == 3 && res.change == 0 && res.has_change == 0,
              "the max-button shape (amount = balance - fee) does sweep the wallet");

        /* wallet.h:111-115: "SEND: spend every input, leave NO change … Overrides
         * want_change".
         * FAILS (see report): wallet.c reads req->want_change but NEVER
         * req->sweep, so a sweep of a smaller amount funds partially and emits
         * change — here 1 input, 2.9 coins of change, 4 coins left unspent. */
        int ok = send_req(2 * COIN_UNIT, FEE_DEFAULT, 0, 1, NULL, 0, NULL, 0, &res);
        CHECK(ok == 1 && res.nins == 3 && res.has_change == 0,
              "sweep=1 spends every input and leaves no change (wallet.h's contract)");

        /* the unambiguous half of the contract: sweep must beat want_change */
        int ok2 = send_req(2 * COIN_UNIT, FEE_DEFAULT, 1, 1, NULL, 0, NULL, 0, &res);
        CHECK(ok2 == 1 && res.has_change == 0,
              "sweep overrides want_change (wallet.h's contract)");
    }

    /* ═══ 11. randomized end-to-end conservation ════════════════════════ */
    printf("-- randomized conservation, 300 full build+sign runs --\n");
    {
        int broken = 0, built = 0, refused = 0, underfunded = 0;
        char lastwhy[128] = "";
        for (int t = 0; t < 300; t++) {
            int n = (int)(sm64() % 12) + 1;
            int64_t v[16];
            int64_t total = 0;
            for (int i = 0; i < n; i++) {
                v[i] = (int64_t)(sm64() % (uint64_t)(20 * COIN_UNIT)) + 1;
                total += v[i];
            }
            db_set_utxos(v, NULL, n);
            int64_t fee = FEE_MIN + (int64_t)(sm64() % (uint64_t)FEE_DEFAULT);
            int64_t amount = DUST + (int64_t)(sm64() % (uint64_t)(total + COIN_UNIT));
            int wc = (int)(sm64() & 1);

            SwlRes res;
            int ok = send_req(amount, fee, wc, 0, NULL, 0, NULL, 0, &res);
            if (!ok) {
                refused++;
                if (res.rawlen || res.txid[0] || res.spent_inputs) broken++;
                continue;
            }
            built++;
            if (res.spent_inputs < amount + fee) underfunded++;
            if (!conserves(&res, amount, fee, why, sizeof why)) {
                broken++;
                snprintf(lastwhy, sizeof lastwhy, "%s", why);
            }
            if (wc && (!res.has_change || res.change < DUST)) {
                broken++;
                snprintf(lastwhy, sizeof lastwhy, "want_change produced no dust-sized change");
            }
        }
        snprintf(name, sizeof name, "%d built + %d refused, all conserving", built, refused);
        CHECK(broken == 0, name);
        if (broken) printf("     (%s)\n", lastwhy);
        CHECK(underfunded == 0, "no built transaction is ever underfunded");
        CHECK(built > 50 && refused > 5, "the random feed exercised both outcomes");
    }

    /* ═══ 12. address helpers, adversarially ════════════════════════════ */
    printf("-- address validation (active coin = pep, version 56) --\n");
    {
        uint8_t h160[20], out[20];
        char addr[64];
        memset(h160, 0x5A, 20);
        CHECK(wallet_h160_addr(h160, addr, sizeof addr) == 1 && addr[0] == 'P',
              "hash160 → a pep P2PKH address");
        CHECK(wallet_addr_valid(addr) == 1, "the encoder's own output validates");
        CHECK(wallet_addr_decode(addr, out) == 1 && !memcmp(out, h160, 20),
              "decode recovers the exact hash160");
        CHECK(wallet_addr_valid(TW.addr) == 1 && wallet_addr_decode(TW.addr, out) == 1 &&
              !memcmp(out, TW.h160, 20), "the test wallet's own address round-trips");

        /* round-trip property */
        int rt_bad = 0;
        for (int t = 0; t < 5000; t++) {
            for (int i = 0; i < 20; i++) h160[i] = (uint8_t)(sm64() >> 24);
            char a[64];
            if (!wallet_h160_addr(h160, a, sizeof a)) { rt_bad++; continue; }
            if (!wallet_addr_valid(a) || !wallet_addr_decode(a, out) || memcmp(out, h160, 20)) rt_bad++;
        }
        CHECK(rt_bad == 0, "5000 random hash160s encode → validate → decode identically");

        /* adversarial */
        CHECK(wallet_addr_valid(NULL) == 0, "NULL address rejected");
        CHECK(wallet_addr_valid("") == 0, "empty address rejected");
        CHECK(wallet_addr_decode(NULL, out) == 0, "NULL address decodes to failure");
        CHECK(wallet_addr_valid("P") == 0, "one-character address rejected");
        CHECK(wallet_addr_valid("PPPPPPPPPP") == 0, "short all-P string rejected");
        CHECK(wallet_addr_valid("DPHNPMCzu76NEmWJZ3s1kBQMZLZBEfPtDX") == 0,
              "a valid DOGE address (version 30) is rejected under coin pep");
        CHECK(wallet_addr_valid("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") == 0,
              "a bitcoin address is rejected");
        {   /* single-character mutation → checksum must catch it */
            char bad[64];
            snprintf(bad, sizeof bad, "%s", TW.addr);
            bad[5] = (bad[5] == 'q') ? 'r' : 'q';
            CHECK(wallet_addr_valid(bad) == 0, "a one-character mutation fails the checksum");
            snprintf(bad, sizeof bad, "%s", TW.addr);
            char tmp = bad[10]; bad[10] = bad[11]; bad[11] = tmp;
            CHECK(wallet_addr_valid(bad) == 0, "two transposed characters fail the checksum");
        }
        CHECK(wallet_addr_valid("P0OIl0OIl0OIl0OIl0OIl0OIl0OIl0OIl0") == 0,
              "the non-base58 characters 0 O I l are rejected");
        {   /* oversize, embedded NUL, non-ASCII, whitespace */
            char big[4096];
            memset(big, 'P', sizeof big - 1); big[sizeof big - 1] = 0;
            CHECK(wallet_addr_valid(big) == 0, "a 4 KB address is rejected without crashing");
            char nul[64];
            snprintf(nul, sizeof nul, "%s", TW.addr);
            nul[8] = 0;
            CHECK(wallet_addr_valid(nul) == 0, "an address truncated by an embedded NUL is rejected");
            char utf[64];
            snprintf(utf, sizeof utf, "P\xc3\xa9%s", TW.addr + 3);
            CHECK(wallet_addr_valid(utf) == 0, "a UTF-8 byte in an address is rejected");
            char sp[80];
            snprintf(sp, sizeof sp, " %s ", TW.addr);
            CHECK(wallet_addr_valid(sp) == 0, "surrounding whitespace is not silently trimmed");
        }
        /* the encoder must fail, not overflow, on a short buffer */
        {
            uint8_t canary[128];
            memset(canary, 0x5A, sizeof canary);
            char *small = (char *)canary + 32;
            int r = wallet_h160_addr(h160, small, 8);
            int intact = 1;
            for (int i = 0; i < 32; i++) if (canary[i] != 0x5A) intact = 0;
            for (size_t i = 32 + 8; i < sizeof canary; i++) if (canary[i] != 0x5A) intact = 0;
            CHECK(r == 0, "encoding into an 8-byte buffer fails");
            CHECK(intact, "…and writes nothing outside it");
            CHECK(wallet_h160_addr(h160, small, 0) == 0, "encoding into a zero-length buffer fails");
        }
    }

    /* ═══ 13. amount parsing ════════════════════════════════════════════ */
    printf("-- parse_amt --\n");
    {
        int64_t v;
        CHECK(parse_amt("1", &v) && v == COIN_UNIT, "\"1\" → 1e8 koinu");
        CHECK(parse_amt("0", &v) && v == 0, "\"0\" → 0");
        CHECK(parse_amt("0.01", &v) && v == DUST, "\"0.01\" → the dust unit");
        CHECK(parse_amt("0.00000001", &v) && v == 1, "\"0.00000001\" → 1 koinu");
        CHECK(parse_amt("1650.25", &v) && v == 1650 * COIN_UNIT + 25000000LL, "\"1650.25\"");
        CHECK(parse_amt(".5", &v) && v == COIN_UNIT / 2, "\".5\" → half a coin");
        CHECK(parse_amt("1.", &v) && v == COIN_UNIT, "\"1.\" → one coin");
        CHECK(!parse_amt("", &v), "empty string rejected");
        CHECK(!parse_amt("x", &v), "\"x\" rejected");
        CHECK(!parse_amt("1.234567890", &v), "9 fractional digits rejected");
        CHECK(!parse_amt("-1", &v), "a negative amount is rejected");
        CHECK(!parse_amt("+1", &v), "a signed amount is rejected");
        CHECK(!parse_amt("1e5", &v), "exponent notation is rejected");
        CHECK(!parse_amt("1 000", &v), "an embedded space is rejected");
        CHECK(!parse_amt("1.2.3", &v), "two decimal points are rejected");
        CHECK(!parse_amt("999999999999999", &v), "a 15-digit whole part is rejected");
#if UBSAN_BUILD
        printf("skip parse_amt overflow probe (UBSan build traps the wrap)\n");
#else
        /* FAILS (see report): wallet.c:311 admits a whole part up to 1e11, but
         * wallet.c:314 then multiplies by 1e8 — 1e19 does not fit in int64_t.
         * The guard must be INT64_MAX / COIN_UNIT = 92233720368. */
        CHECK(!parse_amt("100000000000", &v) || v > 0,
              "a whole part that cannot be scaled to koinu is rejected, not wrapped");
#endif
    }

    /* ── the relay data-carrier policy (--datacarriersize → payload budget) ──
     * The push-encoding math is branchy (direct ≤75 = 1 B overhead, PUSHDATA1
     * ≤255 = 2 B, PUSHDATA2 = 3 B), so pin it at the seams. */
    printf("-- datacarriersize → payload/flag budgets --\n");
    {
        CHECK(swl_datacarriersize() == 83, "default datacarriersize is 83 script bytes");
        CHECK(swl_payload_max() == 80, "83 → 80-byte payload (OP_RETURN + PUSHDATA1 + 80)");
        CHECK(swl_flags_budget_renew() == 71 && swl_flags_budget_xfer() == 51,
              "default budgets are the historical 71/51 flag bytes");
        swl_set_datacarriersize(77);
        CHECK(swl_payload_max() == 75, "77 → 75 (direct push, 1-byte overhead)");
        swl_set_datacarriersize(78);
        CHECK(swl_payload_max() == 75, "78 → 75 (PUSHDATA1 needs ≥76 payload; direct caps at 75)");
        swl_set_datacarriersize(79);
        CHECK(swl_payload_max() == 76, "79 → 76 (the first PUSHDATA1 payload)");
        swl_set_datacarriersize(258);
        CHECK(swl_payload_max() == 255, "258 → 255 (PUSHDATA1 ceiling)");
        swl_set_datacarriersize(260);
        CHECK(swl_payload_max() == 256, "260 → 256 (the first PUSHDATA2 payload)");
        swl_set_datacarriersize(10000);
        CHECK(swl_payload_max() == 9996, "10000 → 9996 (the §6 consensus ceiling)");
        CHECK(swl_flags_budget_renew() == 9987 && swl_flags_budget_xfer() == 9967,
              "at the ceiling the budgets are the §6 consensus flag caps");
        swl_set_datacarriersize(999999);
        CHECK(swl_payload_max() == 9996, "oversize datacarriersize clamps to the consensus ceiling");
        swl_set_datacarriersize(0);
        CHECK(swl_payload_max() >= 5, "degenerate datacarriersize clamps to a usable floor");
        swl_set_datacarriersize(83);    /* restore the default for any later suite */
    }

    unlink(DBP);
    printf("\nt_wallet: %d ok, %d failed\n", g_ok, g_nfail);
    return g_fail;
}
