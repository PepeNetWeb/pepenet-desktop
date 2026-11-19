package main

// Protocol constants (protocol-spec.md §0 table). All consensus-fixed.
const (
	KOINU_PER_DOGE = 100_000_000

	DUST_FLOOR     = 1                 // koinu: rate floor, RESERVE deposit-leg floor, SELL floor basis
	RATE_CAP       = 100_000_000       // 1 DOGE in koinu: rate ceiling
	REF_SIZE       = 200               // bytes: fee-per-byte → per-name rent
	FEE_WINDOW     = 10_081            // blocks (odd): coinbase fee-per-byte median window
	MIN_FEE_SAMPLE = 1000              // min fee-bearing (participant) count for a trusted median; below → DUST_FLOOR (§3.4, boundary inclusive)
	SUBSIDY        = 1_000_000_000_000 // flat 10_000 DOGE in koinu across the reachable window (§3.4)

	LEASE_QUANTUM  = 2_419_200  // s (~28 d): rate anchor
	BILLING_UNIT   = 86_400     // s (1 d): lease-extension granularity
	MAX_LEASE      = 31_536_000 // s (~365 d): cap on lease extension ahead of now
	COMMIT_EXPIRY  = 18_000     // s (~5 h): commit live window (INCLUSIVE)
	RESERVE_WINDOW = 18_000     // s (~5 h): reserve exclusive-buy window; SELL window floor
	DIRECT_WINDOW  = 7_200      // s (~2 h): directed-sale offer window (fixed)
	REORG_BUFFER   = 7_200      // s (~2 h): ordered time-boundary margin

	RESERVE_DEPOSIT_BPS = 100 // 1.00% of price
	RESERVE_BURN_BPS    = 50  // 0.50% burned
	RESERVE_PAY_BPS     = 50  // 0.50% paid to seller

	MAX_ANCHOR_AGE = 1024 // blocks

	// §6 pinned carrier ceiling: a protocol constant, not an L1 rule (L1 never
	// size-checks an OP_RETURN script — unspendable, never executed; only the
	// ~1 MB tx bound applies). Pinned at what a MAX_SCRIPT_SIZE(10000) script
	// would carry, so impl buffers stay fixed-size; relay gates forwarding only.
	L1_SCRIPT_MAX  = 10000
	CARRIER_MAX    = L1_SCRIPT_MAX - 4 // 9996 payload bytes
	BODY_MAX       = CARRIER_MAX - 4   // 9992 after FF 'P' 'N' op
	FLAGS_MAX      = BODY_MAX - 5      // 9987 RENEW/RELEASE bitmap bytes
	FLAGS_XFER_MAX = FLAGS_MAX - 20    // 9967 TRANSFER bitmap bytes

	// Activation height for all name-action opcodes (names-only SM: one gate).
	// The generator pins activation_height=0 (conformance §5). Default 0 so ops
	// are live. See SPEC-RATIONALE.md.
	ACTIVATION_HEIGHT int64 = 0
)

// Opcodes (§2) — contiguous 0x01–0x0F; all gate at ACTIVATION_HEIGHT.
// Removed: VOTE_UP/VOTE_DOWN/DECORATE (overlay). Renumbered order-preserving.
const (
	OP_RENEW_NAME    = 0x01
	OP_TRANSFER_NAME = 0x02
	OP_COMMIT        = 0x03
	OP_CLAIM         = 0x04
	OP_RENEW         = 0x05
	OP_TRANSFER      = 0x06
	OP_SELL          = 0x07
	OP_RESERVE       = 0x08
	OP_SETTLE        = 0x09
	OP_RELEASE       = 0x0A
	OP_RELEASE_NAME  = 0x0B
	OP_SELL_TO       = 0x0C
	OP_PAY           = 0x0D
	OP_AS            = 0x0E
	OP_TRADE         = 0x0F

	OP_MIN = OP_RENEW_NAME
	OP_MAX = OP_TRADE
)

// Name-state enum, digest values pinned by conformance §4.
const (
	ST_OWNED    = 0
	ST_LISTED   = 1
	ST_OFFERED  = 2
	ST_RESERVED = 3
)
