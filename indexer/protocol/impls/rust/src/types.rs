//! Shared types across decode / fold / digest.

pub type Hash160 = [u8; 20];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ScriptType {
    P2pkh = 0,
    P2sh = 1,
}

impl ScriptType {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

// §2 opcodes (contiguous 0x01–0x0F; all gate at ACTIVATION_HEIGHT).
// §6 pinned carrier ceiling: a protocol constant, not an L1 rule (L1 never
// size-checks an OP_RETURN script — unspendable, never executed; only the
// ~1 MB tx bound applies). Pinned at what a MAX_SCRIPT_SIZE(10000) script
// would carry, so impl buffers stay fixed-size; relay gates forwarding only.
pub const L1_SCRIPT_MAX: usize = 10000;
pub const CARRIER_MAX: usize = L1_SCRIPT_MAX - 4; // 9996 payload bytes
pub const BODY_MAX: usize = CARRIER_MAX - 4; // 9992 after FF 'P' 'N' op
pub const FLAGS_MAX: usize = BODY_MAX - 5; // 9987 RENEW/RELEASE bitmap bytes
pub const FLAGS_XFER_MAX: usize = FLAGS_MAX - 20; // 9967 TRANSFER bitmap bytes

pub const OP_RENEW_NAME: u8 = 0x01;
pub const OP_TRANSFER_NAME: u8 = 0x02;
pub const OP_COMMIT: u8 = 0x03;
pub const OP_CLAIM: u8 = 0x04;
pub const OP_RENEW: u8 = 0x05;
pub const OP_TRANSFER: u8 = 0x06;
pub const OP_SELL: u8 = 0x07;
pub const OP_RESERVE: u8 = 0x08;
pub const OP_SETTLE: u8 = 0x09;
pub const OP_RELEASE: u8 = 0x0A;
pub const OP_RELEASE_NAME: u8 = 0x0B;
pub const OP_SELL_TO: u8 = 0x0C;
pub const OP_PAY: u8 = 0x0D;
pub const OP_AS: u8 = 0x0E;
pub const OP_TRADE: u8 = 0x0F;

pub const OP_MIN: u8 = OP_RENEW_NAME;
pub const OP_MAX: u8 = OP_TRADE;

// Protocol constants (§0 table).
pub const DUST_FLOOR: u64 = 1;
pub const RATE_CAP: u64 = 100_000_000; // 1 DOGE in koinu
pub const REF_SIZE: u64 = 200;
pub const FEE_WINDOW: usize = 10_081;
pub const MIN_FEE_SAMPLE: usize = 1_000; // min fee-bearing (participant) count for a trusted median; below → DUST_FLOOR (§3.4, boundary inclusive)
pub const LEASE_QUANTUM: u64 = 2_419_200;
pub const BILLING_UNIT: u64 = 86_400;
pub const MAX_LEASE: u64 = 31_536_000;
pub const COMMIT_EXPIRY: i64 = 18_000;
pub const RESERVE_WINDOW: i64 = 18_000;
pub const DIRECT_WINDOW: i64 = 7_200;
pub const REORG_BUFFER: i64 = 7_200;
pub const RESERVE_DEPOSIT_BPS: u64 = 100;
pub const RESERVE_BURN_BPS: u64 = 50;
pub const RESERVE_PAY_BPS: u64 = 50;
pub const MAX_ANCHOR_AGE: i64 = 1024;

pub const SUBSIDY_FLAT: u64 = 1_000_000_000_000; // 10_000 DOGE in koinu (flat reward window)

/// §3.1 name validation: charset [a-z0-9-], length 1..=32, reject-not-fold;
/// structural (RFC-1123 / IDNA): no leading/trailing hyphen; no `--` at positions 3–4
/// (kills xn-- and every ACE prefix). Every consensus-valid name is a safe hostname label.
pub fn valid_name(b: &[u8]) -> bool {
    if b.is_empty() || b.len() > 32 {
        return false;
    }
    if !b.iter().all(|&c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'-')) {
        return false;
    }
    if b[0] == b'-' || b[b.len() - 1] == b'-' {
        return false;
    }
    if b.len() >= 4 && b[2] == b'-' && b[3] == b'-' {
        return false;
    }
    true
}
