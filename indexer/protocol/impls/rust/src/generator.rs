//! Own internally-consistent generator (`random` mode). This is NOT the reference
//! generator (which is impl-pinned to a forbidden `impls/c/src/gen.c`); it WILL NOT
//! reproduce the reference's frozen seed-goldens. Pin your own (seed,count)→digest.
//! Names-only: market/identity ops only (no votes/posts/decorate).

use crate::digest::state_digest;
use crate::encode::encode_action;
use crate::fold::State;
use crate::model::*;
use crate::prng::SplitMix64;
use crate::sha256::Sha256;
use crate::types::*;
use crate::decode::{Action, RenewMode};

pub const N_IDS: u64 = 16;

pub fn identity(i: u64) -> (Hash160, ScriptType) {
    let mut h = [0u8; 20];
    h[0] = i as u8;
    h[19] = i as u8;
    let st = if i % 4 == 3 { ScriptType::P2sh } else { ScriptType::P2pkh };
    (h, st)
}

fn base36(mut n: u64) -> String {
    if n == 0 {
        return "0".to_string();
    }
    let digits = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut s = Vec::new();
    while n > 0 {
        s.push(digits[(n % 36) as usize]);
        n /= 36;
    }
    s.reverse();
    String::from_utf8(s).unwrap()
}

fn name_of(i: u64) -> Vec<u8> {
    let mut v = vec![b'n'];
    v.extend_from_slice(base36(i).as_bytes());
    v
}

struct Committed {
    name: Vec<u8>,
    salt: [u8; 32],
    author: u64,
}

/// Record the full chain WITHOUT folding inline (mirrors java `Gen.recordChain`).
/// Returns the recorded blocks plus the per-height timestamp array (indexed by height)
/// that `State::apply_block` reads to derive each block's MTP. Any re-fold of the
/// returned blocks must pass back the SAME timestamp slice (it is read at indices < height
/// only, so the whole array is valid for every block).
pub fn record_chain(seed: u64, count: u64) -> (Vec<Block>, Vec<i64>) {
    let mut rng = SplitMix64::new(seed);
    let mut st = State::new(0);
    let mut timestamps: Vec<i64> = Vec::new();
    let base_ts: i64 = 1_700_000_000;
    let mut cur_ts = base_ts;
    let mut committed: Vec<Committed> = Vec::new();
    let mut blocks: Vec<Block> = Vec::new();

    for height in 0..count as i64 {
        let ts_step = 300 + rng.bounded(600) as i64;
        cur_ts += ts_step;
        timestamps.push(cur_ts);
        let rate = 28 * (1 + rng.bounded(4));
        let ntx = 1 + rng.bounded(8);

        let mut txs: Vec<Tx> = Vec::new();
        for txi in 0..ntx {
            let author = rng.bounded(N_IDS);
            let (aid, atype) = identity(author);
            let mut inputs = vec![Input { identity: Some(aid), stype: atype, sighash_all: true }];
            // sometimes a second input (for AS/TRADE)
            let author2 = rng.bounded(N_IDS);
            let (aid2, atype2) = identity(author2);
            inputs.push(Input { identity: Some(aid2), stype: atype2, sighash_all: true });

            let mut outputs: Vec<Output> = Vec::new();
            let op = rng.bounded(11); // names-only op set
            match op {
                0 => {
                    // COMMIT
                    let ni = rng.bounded(400);
                    let name = name_of(ni);
                    let mut salt = [0u8; 32];
                    salt[0..8].copy_from_slice(&rng.next().to_le_bytes());
                    salt[8..16].copy_from_slice(&rng.next().to_le_bytes());
                    let mut pre = Vec::new();
                    pre.extend_from_slice(&salt);
                    pre.extend_from_slice(&name);
                    pre.extend_from_slice(&aid);
                    let commitment = crate::sha256::sha256(&pre);
                    committed.push(Committed { name: name.clone(), salt, author });
                    outputs.push(Output::Carrier {
                        payload: encode_action(&Action::Commit { commitment }),
                        value: 0,
                    });
                }
                1 => {
                    // CLAIM from an earlier commit by this author
                    if let Some(c) = committed.iter().find(|c| c.author == author) {
                        let burn = rate / 28 * (1 + rng.bounded(400)); // exact-day burn
                        outputs.push(Output::Carrier {
                            payload: encode_action(&Action::Claim {
                                salt: c.salt,
                                name: c.name.clone(),
                            }),
                            value: burn,
                        });
                    }
                }
                2 => {
                    // RENEW all
                    let burn = rate / 28 * (1 + rng.bounded(100));
                    outputs.push(Output::Carrier {
                        payload: encode_action(&Action::Renew { mode: RenewMode::All }),
                        value: burn,
                    });
                }
                3 => {
                    // TRANSFER all to another id
                    let (tgt, _) = identity(rng.bounded(N_IDS));
                    outputs.push(Output::Carrier {
                        payload: encode_action(&Action::Transfer { target: tgt, sel: None }),
                        value: 0,
                    });
                }
                4 => {
                    // SELL one owned name
                    let ni = rng.bounded(400);
                    let price = 3 + rng.bounded(1_000_000);
                    outputs.push(Output::Carrier {
                        payload: encode_action(&Action::Sell {
                            price,
                            window: 0,
                            name: name_of(ni),
                        }),
                        value: 0,
                    });
                }
                5 => {
                    // RESERVE (best-effort, with a pay_leg output guess)
                    let ni = rng.bounded(400);
                    outputs.push(Output::Carrier {
                        payload: encode_action(&Action::Reserve { name: name_of(ni) }),
                        value: 1 + rng.bounded(100),
                    });
                    outputs.push(Output::Spend {
                        hash160: aid,
                        stype: atype,
                        value: 1 + rng.bounded(100),
                    });
                }
                6 => {
                    // SETTLE best-effort
                    let ni = rng.bounded(400);
                    outputs.push(Output::Carrier {
                        payload: encode_action(&Action::Settle { name: name_of(ni) }),
                        value: 0,
                    });
                    outputs.push(Output::Spend {
                        hash160: aid,
                        stype: atype,
                        value: 1 + rng.bounded(1_000_000),
                    });
                }
                7 => {
                    // RELEASE selective: release first owned (bitmap bit0)
                    let anchor = (height - 1).max(0);
                    outputs.push(Output::Carrier {
                        payload: encode_action(&Action::Release { anchor, flags: vec![0x01] }),
                        value: 0,
                    });
                }
                8 => {
                    // SELL_TO directed
                    let ni = rng.bounded(400);
                    let (buyer, _) = identity(rng.bounded(N_IDS));
                    let price = 1 + rng.bounded(1_000_000);
                    outputs.push(Output::Carrier {
                        payload: encode_action(&Action::SellTo {
                            price,
                            buyer,
                            name: name_of(ni),
                        }),
                        value: 0,
                    });
                }
                9 => {
                    // PAY best-effort
                    let ni = rng.bounded(400);
                    outputs.push(Output::Carrier {
                        payload: encode_action(&Action::Pay { name: name_of(ni) }),
                        value: 0,
                    });
                    outputs.push(Output::Spend {
                        hash160: aid,
                        stype: atype,
                        value: 1 + rng.bounded(1_000_000),
                    });
                }
                _ => {
                    // AS then RENEW, or TRADE between vin0 and vin1
                    if rng.bounded(2) == 0 {
                        outputs.push(Output::Carrier {
                            payload: encode_action(&Action::As { index: 1 }),
                            value: 0,
                        });
                        let burn = rate / 28 * (1 + rng.bounded(50));
                        outputs.push(Output::Carrier {
                            payload: encode_action(&Action::Renew { mode: RenewMode::All }),
                            value: burn,
                        });
                    } else {
                        let na = name_of(rng.bounded(400));
                        let nb = name_of(rng.bounded(400));
                        outputs.push(Output::Carrier {
                            payload: encode_action(&Action::Trade {
                                idx_a: 0,
                                idx_b: 1,
                                name_a: na,
                                name_b: nb,
                            }),
                            value: 0,
                        });
                    }
                }
            }

            let _ = txi; // txi index retained for parity with input-digest serialization
            txs.push(Tx { inputs, outputs });
        }

        let blk = Block { height, timestamp: cur_ts, rate, txs };
        st.apply_block(&blk, &timestamps);
        blocks.push(blk);
    }

    (blocks, timestamps)
}

/// Streaming input_digest over a recorded chain (this impl's own hash_tx serialization,
/// byte-identical to the prior inline `run_random` stream).
pub fn input_digest(blocks: &[Block]) -> String {
    let mut input_hash = Sha256::new();
    for blk in blocks {
        for (txi, tx) in blk.txs.iter().enumerate() {
            input_hash.update(&(txi as u32).to_le_bytes());
            input_hash.update(&(tx.inputs.len() as u32).to_le_bytes());
            for inp in &tx.inputs {
                input_hash.update(&inp.identity.unwrap_or([0u8; 20]));
            }
            for o in &tx.outputs {
                match o {
                    Output::Carrier { payload, value } => {
                        input_hash.update(&[1u8]);
                        input_hash.update(&(payload.len() as u32).to_le_bytes());
                        input_hash.update(payload);
                        input_hash.update(&value.to_le_bytes());
                    }
                    Output::Spend { hash160, value, .. } => {
                        input_hash.update(&[2u8]);
                        input_hash.update(hash160);
                        input_hash.update(&value.to_le_bytes());
                    }
                }
            }
        }
    }
    crate::digest::hex32(&input_hash.finalize())
}

/// Run the `random` soak. Prints input_digest and state_digest (this impl's own goldens).
pub fn run_random(seed: u64, count: u64) -> (String, String) {
    let (blocks, timestamps) = record_chain(seed, count);
    let mut st = State::new(0);
    for blk in &blocks {
        st.apply_block(blk, &timestamps);
    }
    let id = input_digest(&blocks);
    let sd = crate::digest::hex32(&state_digest(&st));
    (id, sd)
}
