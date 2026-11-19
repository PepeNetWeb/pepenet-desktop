// txcheck.h — context-free (no-UTXO-set) transaction validation for the relay
// mempool. We are an SPV node: we do NOT hold the UTXO set, so we CANNOT verify
// that an input exists, check a signature (needs the prevout's scriptPubKey), or
// detect a chain double-spend. What we CAN do is every check that depends only on
// the transaction's own bytes — the consensus context-free checks plus relay
// standardness — so obvious junk never enters our pool or gets rebroadcast to the
// mesh. An invalid-but-well-formed tx that slips through simply never confirms
// (miners with the UTXO set reject it); the size/dust/standardness limits here
// bound the bandwidth cost of that residual.
#ifndef IDX_TXCHECK_H
#define IDX_TXCHECK_H

#include <stdint.h>
#include <stddef.h>

// Relay policy limits (see the mempool for pool-level caps).
#define TX_MIN_SIZE        61          // no real tx serializes smaller
#define TX_MAX_SIZE        100000      // 100 KB — the standard max-standard-tx size
#define TX_MAX_SCRIPTSIG   1650        // per-input scriptSig cap (a 15-of-15 P2SH redeem)
#define TX_DUST_LIMIT      1000000LL   // 0.01 coin (Dogecoin-1.14 threshold)
#define TX_RELAY_CARRIER_MAX 80        // relay-standard payload (datacarriersize 83);
                                       // the FOLD accepts up to SM_CARRIER_MAX (§6)
// Doge-family money-range sanity bound (Dogecoin has no hard supply cap; Core
// uses this as the CheckTransaction value range). = 1e10 coins in koinu.
#define TX_MAX_MONEY       (10000000000LL * 100000000LL)

// Validate a standalone serialized transaction with only its own bytes.
// Returns 1 if it passes every context-free + standardness check, else 0 and
// writes a short human reason into `reason` (may be NULL). See the .c for the
// exact rule list.
int txcheck_stateless(const uint8_t *raw, size_t len, char *reason, size_t reason_cap);

#endif
