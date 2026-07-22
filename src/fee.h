// fee.h — the network-fee quote: §3.4's oracle mechanics, re-aimed at "what
// should MY next tx attach?" instead of "what is a name-quantum worth?".
#ifndef SHIB_FEE_H
#define SHIB_FEE_H

#include <stdint.h>

// The relay floor (wallet FEE_MIN, Dogecoin-1.14's 0.001) — the quote
// never goes below it, and it is the honest answer on a fee-quiet chain.
#define FEE_FLOOR_K     100000LL

// Grief bound, same philosophy as SM_RATE_CAP: miners can inflate their own
// coinbase for free (they pay themselves), so an uncapped quote lets a
// colluding stretch of blocks drain wallets. 100× the floor (0.1 Ᵽ) leaves
// two decades of congestion headroom while bounding the damage per tx.
#define FEE_CAP_K       (100 * FEE_FLOOR_K)

// The consensus rate samples SM_FEE_WINDOW (10081) blocks because rent must
// be slow and spoof-resistant. A fee quote wants the opposite tradeoff:
// track congestion NOW. 144 pep blocks ≈ the last 2½ hours.
#define FEE_EST_WINDOW  144

// Below this many fee-bearing blocks the 3rd quartile is noise — degrade to
// the floor, don't extrapolate (the oracle's own rule, scaled to our window).
#define FEE_MIN_SAMPLE  4

// koinu/byte → koinu/tx. §3.4 converts with SM_REF_SIZE (200 B, a reference
// tx); we convert with OUR shape: legacy P2PKH, 10 B overhead + 2 inputs
// (2×148) + 2 outputs (2×34) + a §3 carrier (~90 B) ≈ 460 → 480 with slack.
#define FEE_TX_BYTES    480

// Per-block inputs are the SAME feed the §3.4 rate reads (the indexer's
// blocks table): fees are inferred coinbase − subsidy, so no prevouts are
// needed. Returns the per-tx quote in koinu, always in [FLOOR, CAP].
int64_t fee_estimate(const int64_t *coinbase, const int64_t *block_bytes,
                     int n, int64_t subsidy);

#endif
