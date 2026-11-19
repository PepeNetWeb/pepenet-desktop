// txcheck.c — see txcheck.h. Context-free tx validation over the tx's own bytes.
#include "txcheck.h"
#include "chain.h"
#include <string.h>
#include <stdio.h>

static int fail(char *r, size_t cap, const char *why) {
    if (r && cap) snprintf(r, cap, "%s", why);
    return 0;
}

// A standard scriptSig is PUSH-ONLY: it only pushes data, never executes an
// opcode. Walk it, stepping over each push's data; reject the moment we see any
// opcode above OP_16 (0x60). Bounds-checked against a truncated push length.
static int script_push_only(const uint8_t *s, size_t n) {
    size_t i = 0;
    while (i < n) {
        uint8_t op = s[i++];
        if (op > 0x60) return 0;                 // a non-push opcode → not push-only
        size_t len = 0;
        if (op < 0x4c) len = op;                  // direct push (0x00..0x4b)
        else if (op == 0x4c) { if (i + 1 > n) return 0; len = s[i]; i += 1; }             // PUSHDATA1
        else if (op == 0x4d) { if (i + 2 > n) return 0; len = s[i] | (s[i+1] << 8); i += 2; } // PUSHDATA2
        else if (op == 0x4e) { if (i + 4 > n) return 0;                                    // PUSHDATA4
                               len = s[i] | (s[i+1] << 8) | (s[i+2] << 16) | ((size_t)s[i+3] << 24); i += 4; }
        // 0x4f (OP_1NEGATE), 0x50, 0x51..0x60 (OP_1..OP_16): opcodes with no payload
        if (len > n - i) return 0;                // push runs off the end
        i += len;
    }
    return 1;
}

int txcheck_stateless(const uint8_t *raw, size_t len, char *reason, size_t rc) {
    if (len < TX_MIN_SIZE) return fail(reason, rc, "tx too small");
    if (len > TX_MAX_SIZE) return fail(reason, rc, "tx exceeds 100KB");

    IdxTx tx;
    if (!idx_tx_parse(raw, len, &tx)) return fail(reason, rc, "malformed/segwit tx");

    int ok = 1; const char *why = NULL;
    do {
        if (tx.n_in  < 1) { ok = 0; why = "no inputs";  break; }
        if (tx.n_out < 1) { ok = 0; why = "no outputs"; break; }

        // reject a loose coinbase (null prevout): unrelayable outside a block
        if (tx.n_in == 1) {
            const uint8_t *po = tx.ins[0].prevout;
            int nullhash = 1; for (int b = 0; b < 32; b++) if (po[b]) { nullhash = 0; break; }
            uint32_t vout = (uint32_t)po[32] | (uint32_t)po[33] << 8 |
                            (uint32_t)po[34] << 16 | (uint32_t)po[35] << 24;
            if (nullhash && vout == 0xFFFFFFFF) { ok = 0; why = "coinbase tx"; break; }
        }

        // no duplicate prevout within the tx (an in-tx double-spend)
        for (int a = 0; a < tx.n_in && ok; a++)
            for (int b = a + 1; b < tx.n_in; b++)
                if (!memcmp(tx.ins[a].prevout, tx.ins[b].prevout, 36)) { ok = 0; why = "duplicate input"; break; }
        if (!ok) break;

        // scriptSig: bounded + push-only (standardness)
        for (int i = 0; i < tx.n_in; i++) {
            if (tx.ins[i].sslen > TX_MAX_SCRIPTSIG) { ok = 0; why = "scriptSig too large"; break; }
            if (!script_push_only(tx.ins[i].scriptsig, tx.ins[i].sslen)) { ok = 0; why = "scriptSig not push-only"; break; }
        }
        if (!ok) break;

        // outputs: value range, running sum, standard template, dust
        int64_t total = 0;
        for (int o = 0; o < tx.n_out; o++) {
            int64_t v = tx.outs[o].value;
            if (v < 0 || v > TX_MAX_MONEY) { ok = 0; why = "output value out of range"; break; }
            total += v;
            if (total < 0 || total > TX_MAX_MONEY) { ok = 0; why = "output total out of range"; break; }

            uint8_t h160[20], type; const uint8_t *d; size_t dl;
            if (idx_script_payee(tx.outs[o].spk, tx.outs[o].spklen, h160, &type)) {
                if (v < TX_DUST_LIMIT) { ok = 0; why = "dust output"; break; }   // P2PKH / P2SH
            } else if (idx_op_return_payload(tx.outs[o].spk, tx.outs[o].spklen, &d, &dl)) {
                // carrier (namespace op) — exempt from dust; value is protocol-meaningful.
                // RELAY policy (this gate) keeps the network-standard 80-byte payload
                // (datacarriersize 83); the FOLD accepts up to the §6 consensus ceiling
                // (SM_CARRIER_MAX) once mined — chain.c extracts at the consensus bound,
                // this mempool forwards only what the rest of the network will.
                if (dl > TX_RELAY_CARRIER_MAX) { ok = 0; why = "carrier past relay datacarriersize"; break; }
            } else {
                ok = 0; why = "nonstandard scriptPubKey"; break;
            }
        }
        if (!ok) break;
    } while (0);

    idx_tx_free(&tx);
    if (!ok) return fail(reason, rc, why ? why : "invalid tx");
    return 1;
}
