//! Canonical action encoder — the inverse of decode.rs (round-trip tested in selftest).

use crate::decode::*;
use crate::types::*;

fn hdr(op: u8) -> Vec<u8> {
    vec![0xFF, 0x50, 0x4E, op]
}

pub fn encode_action(a: &Action) -> Vec<u8> {
    match a {
        Action::Commit { commitment } => {
            let mut v = hdr(OP_COMMIT);
            v.extend_from_slice(commitment);
            v
        }
        Action::Claim { salt, name } => {
            let mut v = hdr(OP_CLAIM);
            v.extend_from_slice(salt);
            v.extend_from_slice(name);
            v
        }
        Action::Renew { mode } => {
            let mut v = hdr(OP_RENEW);
            match mode {
                RenewMode::All => {}
                RenewMode::AllSafe { anchor } => v.extend_from_slice(&h5(*anchor)),
                RenewMode::Selective { anchor, flags } => {
                    v.extend_from_slice(&h5(*anchor));
                    v.extend_from_slice(flags);
                }
            }
            v
        }
        Action::Transfer { target, sel } => {
            let mut v = hdr(OP_TRANSFER);
            v.extend_from_slice(target);
            if let Some(BitmapSel { anchor, flags }) = sel {
                v.extend_from_slice(&h5(*anchor));
                v.extend_from_slice(flags);
            }
            v
        }
        Action::Sell { price, window, name } => {
            let mut v = hdr(OP_SELL);
            v.extend_from_slice(&price.to_le_bytes());
            v.extend_from_slice(&window.to_le_bytes());
            v.extend_from_slice(name);
            v
        }
        Action::RenewName { name } => {
            let mut v = hdr(OP_RENEW_NAME);
            v.extend_from_slice(name);
            v
        }
        Action::TransferName { target, name } => {
            let mut v = hdr(OP_TRANSFER_NAME);
            v.extend_from_slice(target);
            v.extend_from_slice(name);
            v
        }
        Action::ReleaseName { name } => {
            let mut v = hdr(OP_RELEASE_NAME);
            v.extend_from_slice(name);
            v
        }
        Action::Reserve { name } => {
            let mut v = hdr(OP_RESERVE);
            v.extend_from_slice(name);
            v
        }
        Action::Settle { name } => {
            let mut v = hdr(OP_SETTLE);
            v.extend_from_slice(name);
            v
        }
        Action::Release { anchor, flags } => {
            let mut v = hdr(OP_RELEASE);
            v.extend_from_slice(&h5(*anchor));
            v.extend_from_slice(flags);
            v
        }
        Action::SellTo { price, buyer, name } => {
            let mut v = hdr(OP_SELL_TO);
            v.extend_from_slice(&price.to_le_bytes());
            v.extend_from_slice(buyer);
            v.extend_from_slice(name);
            v
        }
        Action::Pay { name } => {
            let mut v = hdr(OP_PAY);
            v.extend_from_slice(name);
            v
        }
        Action::As { index } => {
            let mut v = hdr(OP_AS);
            v.push(*index);
            v
        }
        Action::Trade { idx_a, idx_b, name_a, name_b } => {
            let mut v = hdr(OP_TRADE);
            v.push(*idx_a);
            v.push(*idx_b);
            v.extend_from_slice(name_a);
            v.push(b',');
            v.extend_from_slice(name_b);
            v
        }
    }
}

fn h5(v: i64) -> [u8; 5] {
    let u = v as u64;
    [
        (u & 0xff) as u8,
        ((u >> 8) & 0xff) as u8,
        ((u >> 16) & 0xff) as u8,
        ((u >> 24) & 0xff) as u8,
        ((u >> 32) & 0xff) as u8,
    ]
}
