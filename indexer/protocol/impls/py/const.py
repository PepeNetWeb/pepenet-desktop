"""Protocol constants (protocol-spec.md §0 table) and digest enums.

Clean-room: every value is transcribed directly from the spec table; none is
imported from any external implementation.
"""

# §0 protocol constants
KOINU_PER_DOGE = 100_000_000
DUST_FLOOR = 1
RATE_CAP = 100_000_000           # 1 DOGE in koinu
REF_SIZE = 200
FEE_WINDOW = 10_081              # odd
MIN_FEE_SAMPLE = 1_000           # min fee-bearing (participant) count for a trusted median; below -> DUST_FLOOR (§3.4, boundary inclusive)
LEASE_QUANTUM = 2_419_200        # ~28 d, seconds
BILLING_UNIT = 86_400           # 1 d, seconds
MAX_LEASE = 31_536_000          # ~365 d, seconds
COMMIT_EXPIRY = 18_000          # ~5 h, seconds
RESERVE_WINDOW = 18_000
DIRECT_WINDOW = 7_200
REORG_BUFFER = 7_200
RESERVE_DEPOSIT_BPS = 100
RESERVE_BURN_BPS = 50
RESERVE_PAY_BPS = 50
MAX_ANCHOR_AGE = 1024

# §6 pinned carrier ceiling: a protocol constant, not an L1 rule (L1 never
# size-checks an OP_RETURN script — unspendable, never executed; only the
# ~1 MB tx bound applies). Pinned at what a MAX_SCRIPT_SIZE(10000) script
# would carry, so impl buffers stay fixed-size; relay gates forwarding only.
L1_SCRIPT_MAX = 10_000
CARRIER_MAX = L1_SCRIPT_MAX - 4      # 9_996 payload bytes
BODY_MAX = CARRIER_MAX - 4           # 9_992 after FF 'P' 'N' op
FLAGS_MAX = BODY_MAX - 5             # 9_987 RENEW/RELEASE bitmap bytes
FLAGS_XFER_MAX = FLAGS_MAX - 20      # 9_967 TRANSFER bitmap bytes

# §3.4 / §5 generator-pinned: Dogecoin flat subsidy across reachable window.
SUBSIDY = 10_000 * KOINU_PER_DOGE   # 1_000_000_000_000 koinu

# Fixed-width masks (Python int is unbounded — these are load-bearing, see SPEC-RATIONALE.md).
MASK64 = (1 << 64) - 1
MASK128 = (1 << 128) - 1

# Opcodes (§2) — contiguous 0x01–0x0F; all gate at ACTIVATION_HEIGHT
OP_RENEW_NAME = 0x01
OP_TRANSFER_NAME = 0x02
OP_COMMIT = 0x03
OP_CLAIM = 0x04
OP_RENEW = 0x05
OP_TRANSFER = 0x06
OP_SELL = 0x07
OP_RESERVE = 0x08
OP_SETTLE = 0x09
OP_RELEASE = 0x0A
OP_RELEASE_NAME = 0x0B
OP_SELL_TO = 0x0C
OP_PAY = 0x0D
OP_AS = 0x0E
OP_TRADE = 0x0F

PREFIX = bytes([0xFF, 0x50, 0x4E])   # 0xFF 'P' 'N'

# names-row state enum (SPEC-conformance.md §4)
ST_OWNED = 0
ST_LISTED = 1
ST_OFFERED = 2
ST_RESERVED = 3

# Script types (§4 Rule 2)
TYPE_P2PKH = 0
TYPE_P2SH = 1


def mask_u64(x):
    return x & MASK64
