//! Strict, fail-closed wire decoder (§0/§1/§2 + conformance §9).
//! A malformed action NEVER panics — it returns Ignore. ACTION | IGNORE only
//! (names-only: posts/votes/decorations are overlay concerns, consensus-ignored).

use crate::types::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Commit { commitment: [u8; 32] },
    Claim { salt: [u8; 32], name: Vec<u8> },
    Renew { mode: RenewMode },
    Transfer { target: Hash160, sel: Option<BitmapSel> },
    RenewName { name: Vec<u8> },
    TransferName { target: Hash160, name: Vec<u8> },
    ReleaseName { name: Vec<u8> },
    Sell { price: u64, window: u32, name: Vec<u8> },
    Reserve { name: Vec<u8> },
    Settle { name: Vec<u8> },
    Release { anchor: i64, flags: Vec<u8> },
    SellTo { price: u64, buyer: Hash160, name: Vec<u8> },
    Pay { name: Vec<u8> },
    As { index: u8 },
    Trade { idx_a: u8, idx_b: u8, name_a: Vec<u8>, name_b: Vec<u8> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RenewMode {
    All,                              // bl == 0
    AllSafe { anchor: i64 },          // bl == 5
    Selective { anchor: i64, flags: Vec<u8> }, // bl 6..=BODY_MAX
}

/// A bitmap selection (anchor + flag bytes), used by TRANSFER selective.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitmapSel {
    pub anchor: i64,
    pub flags: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decoded {
    Action(Action),
    Ignore,
}

#[inline]
fn rd_u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
#[inline]
fn rd_u64_le(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    u64::from_le_bytes(a)
}
/// 5-byte little-endian height anchor → i64 (fits comfortably).
#[inline]
fn rd_h5_le(b: &[u8]) -> i64 {
    (b[0] as i64)
        | ((b[1] as i64) << 8)
        | ((b[2] as i64) << 16)
        | ((b[3] as i64) << 24)
        | ((b[4] as i64) << 32)
}

/// Top-level demux. `value` is unused (kept for call-site uniformity); consensus
/// recognizes only the 0xFF 'P' 'N' + opcode 0x01..0x0C name-action shape.
pub fn decode_payload(payload: &[u8], _value: u64) -> Decoded {
    // §1 action recognition: prefix 0xFF 'P' 'N' + opcode 0x01..0x0C.
    if payload.len() >= 4 && payload[0] == 0xFF && payload[1] == 0x50 && payload[2] == 0x4E {
        let op = payload[3];
        if op >= OP_MIN && op <= OP_MAX {
            if let Some(a) = decode_action(op, &payload[4..]) {
                return Decoded::Action(a);
            }
        }
        return Decoded::Ignore; // malformed / unknown opcode / overlay band
    }
    // everything else (UTF-8 noise, overlay, empty) → IGNORE
    Decoded::Ignore
}

fn decode_action(opcode: u8, b: &[u8]) -> Option<Action> {
    let bl = b.len();
    match opcode {
        OP_COMMIT => {
            if bl != 32 {
                return None;
            }
            let mut c = [0u8; 32];
            c.copy_from_slice(&b[..32]);
            Some(Action::Commit { commitment: c })
        }
        OP_CLAIM => {
            // salt32 + name1..32  → bl 33..=64
            if bl < 33 || bl > 64 {
                return None;
            }
            let name = &b[32..];
            if !valid_name(name) {
                return None;
            }
            let mut salt = [0u8; 32];
            salt.copy_from_slice(&b[..32]);
            Some(Action::Claim { salt, name: name.to_vec() })
        }
        OP_RENEW => match bl {
            0 => Some(Action::Renew { mode: RenewMode::All }),
            5 => Some(Action::Renew {
                mode: RenewMode::AllSafe { anchor: rd_h5_le(&b[..5]) },
            }),
            6..=BODY_MAX => Some(Action::Renew {
                mode: RenewMode::Selective {
                    anchor: rd_h5_le(&b[..5]),
                    flags: b[5..].to_vec(),
                },
            }),
            _ => None, // bl 1..4 invalid
        },
        OP_TRANSFER => {
            // all: bl==20 ; selective: 20+anchor5+flags1..FLAGS_XFER_MAX → bl 26..=BODY_MAX
            if bl == 20 {
                let mut t = [0u8; 20];
                t.copy_from_slice(&b[..20]);
                Some(Action::Transfer { target: t, sel: None })
            } else if (26..=BODY_MAX).contains(&bl) {
                let mut t = [0u8; 20];
                t.copy_from_slice(&b[..20]);
                let anchor = rd_h5_le(&b[20..25]);
                let flags = b[25..].to_vec();
                Some(Action::Transfer {
                    target: t,
                    sel: Some(BitmapSel { anchor, flags }),
                })
            } else {
                None
            }
        }
        OP_SELL => {
            // price8 + window4 + name1..32 → bl 13..=44
            if bl < 13 || bl > 44 {
                return None;
            }
            let name = &b[12..];
            if !valid_name(name) {
                return None;
            }
            let price = rd_u64_le(&b[..8]);
            let window = rd_u32_le(&b[8..12]);
            Some(Action::Sell { price, window, name: name.to_vec() })
        }
        OP_RENEW_NAME | OP_RELEASE_NAME | OP_RESERVE | OP_SETTLE | OP_PAY => {
            // name1..32 → bl 1..=32
            if bl < 1 || bl > 32 {
                return None;
            }
            if !valid_name(b) {
                return None;
            }
            let name = b.to_vec();
            Some(match opcode {
                OP_RENEW_NAME => Action::RenewName { name },
                OP_RELEASE_NAME => Action::ReleaseName { name },
                OP_RESERVE => Action::Reserve { name },
                OP_SETTLE => Action::Settle { name },
                _ => Action::Pay { name },
            })
        }
        OP_TRANSFER_NAME => {
            // target20 + name1..32 → bl 21..=52
            if bl < 21 || bl > 52 {
                return None;
            }
            let name = &b[20..];
            if !valid_name(name) {
                return None;
            }
            let mut t = [0u8; 20];
            t.copy_from_slice(&b[..20]);
            Some(Action::TransferName { target: t, name: name.to_vec() })
        }
        OP_RELEASE => {
            // anchor5 + flags1..FLAGS_MAX → bl 6..=BODY_MAX
            if bl < 6 || bl > BODY_MAX {
                return None;
            }
            let anchor = rd_h5_le(&b[..5]);
            Some(Action::Release { anchor, flags: b[5..].to_vec() })
        }
        OP_SELL_TO => {
            // price8 + buyer20 + name1..32 → bl 29..=60
            if bl < 29 || bl > 60 {
                return None;
            }
            let name = &b[28..];
            if !valid_name(name) {
                return None;
            }
            let price = rd_u64_le(&b[..8]);
            let mut buyer = [0u8; 20];
            buyer.copy_from_slice(&b[8..28]);
            Some(Action::SellTo { price, buyer, name: name.to_vec() })
        }
        OP_AS => {
            if bl != 1 {
                return None;
            }
            Some(Action::As { index: b[0] })
        }
        OP_TRADE => {
            // idxA1 + idxB1 + nameA,nameB ; exactly one 0x2C
            if bl < 5 {
                return None;
            }
            let idx_a = b[0];
            let idx_b = b[1];
            let names = &b[2..];
            // exactly one comma
            let commas = names.iter().filter(|&&c| c == b',').count();
            if commas != 1 {
                return None;
            }
            let pos = names.iter().position(|&c| c == b',').unwrap();
            let name_a = &names[..pos];
            let name_b = &names[pos + 1..];
            if !valid_name(name_a) || !valid_name(name_b) {
                return None;
            }
            Some(Action::Trade {
                idx_a,
                idx_b,
                name_a: name_a.to_vec(),
                name_b: name_b.to_vec(),
            })
        }
        _ => None, // outside 0x01..0x0C
    }
}
