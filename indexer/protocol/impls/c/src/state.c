// State container + shared helpers + queries. See sm.h.
#include "sm.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define GROW(arr, n, cap, T) do {                                    \
    if ((n) == (cap)) {                                              \
        int _nc = (cap) ? (cap) * 2 : 16;                           \
        T *_p = realloc((arr), (size_t)_nc * sizeof(T));            \
        assert(_p); (arr) = _p; (cap) = _nc;                        \
    } } while (0)

static int h160_eq(const uint8_t a[20], const uint8_t b[20]) { return memcmp(a, b, 20) == 0; }

// ── lifecycle ───────────────────────────────────────────────────────────────

SmState *sm_new(uint64_t activation_height) {
    SmState *s = calloc(1, sizeof(SmState));
    assert(s);
    s->activation_height = activation_height;
    return s;
}

void sm_free(SmState *s) {
    if (!s) return;
    free(s->names); free(s->commits); free(s->muts); free(s->claimsc);
    free(s);
}

void sm_clear(SmState *s) {
    s->n_names = s->n_commits = s->n_muts = s->n_claimsc = 0;
    s->cur_height = s->cur_mtp = 0; s->cur_rate = 0;
}

// ── §3.1 name validation ─────────────────────────────────────────────────────

int sm_name_valid(const char *name, size_t len) {
    if (len < 1 || len > SM_NAME_MAX) return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)name[i];
        // charset: [a-z0-9-] — a DNS label, lowercased. reject, never fold.
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return 0;
    }
    // structural (RFC-1123 / IDNA): no leading/trailing hyphen; no `--` at 3–4
    // (kills xn-- and every ACE prefix). Every consensus-valid name is a safe hostname label.
    if (name[0] == '-' || name[len - 1] == '-') return 0;
    if (len >= 4 && name[2] == '-' && name[3] == '-') return 0;
    return 1;
}

// ── SmTx dynamic arrays (§0: no per-tx count cap) ────────────────────────────
// Append one zeroed slot, spilling inline→heap past SM_INLINE_*. Never returns
// NULL (malloc failure aborts — a conformance tool, not production). Build in
// place only: an SmTx's pointers reference its own inline buffers, so copying it
// by value would dangle them.
SmId *sm_tx_input(SmTx *t) {
    if (t->cap_inputs == 0) { t->inputs = t->in_inline; t->in_sighash_all = t->sig_inline; t->cap_inputs = SM_INLINE_INPUTS; }
    if (t->n_inputs == t->cap_inputs) {
        int nc = t->cap_inputs * 2;
        SmId *ni; uint8_t *ns;
        if (t->inputs == t->in_inline) {
            ni = malloc((size_t)nc * sizeof *ni); ns = malloc((size_t)nc);
            assert(ni && ns);
            memcpy(ni, t->inputs, (size_t)t->n_inputs * sizeof *ni);
            memcpy(ns, t->in_sighash_all, (size_t)t->n_inputs);
        } else {
            ni = realloc(t->inputs, (size_t)nc * sizeof *ni);
            ns = realloc(t->in_sighash_all, (size_t)nc);
            assert(ni && ns);
        }
        t->inputs = ni; t->in_sighash_all = ns; t->cap_inputs = nc;
    }
    SmId *slot = &t->inputs[t->n_inputs];
    memset(slot, 0, sizeof *slot);
    t->in_sighash_all[t->n_inputs] = 0;
    t->n_inputs++;
    return slot;
}
SmCarrier *sm_tx_carrier(SmTx *t) {
    if (t->cap_carriers == 0) { t->carriers = t->car_inline; t->cap_carriers = SM_INLINE_CARRIERS; }
    if (t->n_carriers == t->cap_carriers) {
        int nc = t->cap_carriers * 2;
        SmCarrier *np;
        if (t->carriers == t->car_inline) { np = malloc((size_t)nc * sizeof *np); assert(np); memcpy(np, t->carriers, (size_t)t->n_carriers * sizeof *np); }
        else { np = realloc(t->carriers, (size_t)nc * sizeof *np); assert(np); }
        t->carriers = np; t->cap_carriers = nc;
    }
    SmCarrier *slot = &t->carriers[t->n_carriers++];
    memset(slot, 0, sizeof *slot);
    return slot;
}
SmOut *sm_tx_out(SmTx *t) {
    if (t->cap_outs == 0) { t->outs = t->out_inline; t->cap_outs = SM_INLINE_OUTS; }
    if (t->n_outs == t->cap_outs) {
        int nc = t->cap_outs * 2;
        SmOut *np;
        if (t->outs == t->out_inline) { np = malloc((size_t)nc * sizeof *np); assert(np); memcpy(np, t->outs, (size_t)t->n_outs * sizeof *np); }
        else { np = realloc(t->outs, (size_t)nc * sizeof *np); assert(np); }
        t->outs = np; t->cap_outs = nc;
    }
    SmOut *slot = &t->outs[t->n_outs++];
    memset(slot, 0, sizeof *slot);
    return slot;
}
void sm_tx_free(SmTx *t) {
    if (t->inputs && t->inputs != t->in_inline) { free(t->inputs); free(t->in_sighash_all); }
    if (t->carriers && t->carriers != t->car_inline) free(t->carriers);
    if (t->outs && t->outs != t->out_inline) free(t->outs);
    t->inputs = NULL; t->in_sighash_all = NULL; t->carriers = NULL; t->outs = NULL;
    t->n_inputs = t->cap_inputs = t->n_carriers = t->cap_carriers = t->n_outs = t->cap_outs = 0;
}

// ── owned-set rows ────────────────────────────────────────────────────────────

SmNameRow *sm_find_name(SmState *s, const char *name) {
    for (int i = 0; i < s->n_names; i++)
        if (strcmp(s->names[i].name, name) == 0) return &s->names[i];
    return NULL;
}

SmNameRow *sm_add_name(SmState *s, const char *name, size_t len) {
    GROW(s->names, s->n_names, s->cap_names, SmNameRow);
    SmNameRow *r = &s->names[s->n_names++];
    memset(r, 0, sizeof(*r));
    memcpy(r->name, name, len);
    r->name[len] = '\0';
    r->name_len = (uint8_t)len;
    return r;
}

void sm_remove_name(SmState *s, SmNameRow *row) {
    int i = (int)(row - s->names);
    if (i < 0 || i >= s->n_names) return;
    s->names[i] = s->names[--s->n_names];   // order-independent (lookups are by name)
}

// ── commits (§3.2) ───────────────────────────────────────────────────────────

void sm_commit_add(SmState *s, const uint8_t commitment[32], int64_t height,
                   uint32_t txidx, int64_t time) {
    GROW(s->commits, s->n_commits, s->cap_commits, SmCommit);
    SmCommit *c = &s->commits[s->n_commits++];
    memset(c, 0, sizeof(*c));
    memcpy(c->commitment, commitment, 32);
    c->commit_height = height; c->tx_index = txidx; c->commit_time = time;
}

// ── per-owner last mutation height (§3.5 anchor guard) ───────────────────────

int64_t sm_last_mutation(SmState *s, const uint8_t owner[20]) {
    for (int i = 0; i < s->n_muts; i++)
        if (h160_eq(s->muts[i].owner, owner)) return s->muts[i].height;
    return 0;
}

void sm_bump_mutation(SmState *s, const uint8_t owner[20], int64_t height) {
    for (int i = 0; i < s->n_muts; i++)
        if (h160_eq(s->muts[i].owner, owner)) {
            if (height > s->muts[i].height) s->muts[i].height = height;   // monotonic
            return;
        }
    GROW(s->muts, s->n_muts, s->cap_muts, SmMut);
    SmMut *m = &s->muts[s->n_muts++];
    memcpy(m->owner, owner, 20); m->height = height;
}

// ── queries ───────────────────────────────────────────────────────────────────

const SmNameRow *sm_lookup(SmState *s, const char *name) { return sm_find_name(s, name); }

int sm_owns(SmState *s, const uint8_t h160[20], const char *name) {
    SmNameRow *r = sm_find_name(s, name);
    return r && r->st == SM_OWNED && h160_eq(r->owner, h160);
}
