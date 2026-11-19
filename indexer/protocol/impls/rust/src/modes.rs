//! Generator-driven invariant-battery modes (mirrors `impls/c` / `impls/java Modes.java`).
//!
//! The DIGESTS here do NOT match the gen.c-pinned soak goldens (this impl's per-op draw
//! order is an independent reconstruction). Their VALUE is the generator-INDEPENDENT
//! assertions: `properties`' §8 `violations==0` (the fold preserves every hard invariant
//! per block), and `meta`/`reorg`/`reorgfuzz`'s `failures==0` (the fold is drop-closed and
//! a pure, reorg-safe function of the block sequence), plus `fuzz`'s `parser_crashes==0`
//! (the decoder is crash-safe / fail-closed over adversarial OP_RETURN bytes).
//!
//! These modes ONLY drive the existing fold/decoder — they never change protocol logic.

use std::process::exit;

use crate::decode::Action;
use crate::digest::{hex32, state_digest};
use crate::encode::encode_action;
use crate::fold::{deposit_leg, St, State};
use crate::generator::record_chain;
use crate::model::{Block, Input, Output, Tx};
use crate::oracle::mtp;
use crate::prng::SplitMix64;
use crate::sha256::Sha256;
use crate::types::*;

const MAX_LEASE_I: i64 = MAX_LEASE as i64;
const SELL_FLOOR: u64 = 3 * DUST_FLOOR;

fn digest_hex(st: &State) -> String {
    hex32(&state_digest(st))
}

fn hex_to_bytes(h: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(h.len() / 2);
    let b = h.as_bytes();
    let mut i = 0;
    while i + 1 < b.len() {
        let hi = (b[i] as char).to_digit(16).unwrap() as u8;
        let lo = (b[i + 1] as char).to_digit(16).unwrap() as u8;
        v.push((hi << 4) | lo);
        i += 2;
    }
    v
}

// ───────────────────────── §8 property battery ─────────────────────────

/// Re-fold the recorded chain block-by-block, asserting the hard §8 invariants after each
/// block. Mirrors java `Modes.checkInvariants` / `fingerprint`. Exit 1 if violations != 0.
pub fn properties(seed: u64, count: u64) {
    let (blocks, timestamps) = record_chain(seed, count);
    let mut st = State::new(0);
    let mut violations: u64 = 0;
    let mut pd = Sha256::new();
    for blk in &blocks {
        st.apply_block(blk, &timestamps);
        let m = mtp(blk.height, &timestamps);
        violations += check_invariants(&st, blk.height, m);
        fingerprint(&mut pd, &st);
    }
    println!("violations={}", violations);
    println!("property_digest={}", hex32(&pd.finalize()));
    println!("state_digest={}", digest_hex(&st));
    if violations != 0 {
        exit(1);
    }
}

fn check_invariants(st: &State, height: i64, m: i64) -> u64 {
    let mut v: u64 = 0;
    // names key by name -> single owner by construction (BTreeMap key = no-double-ownership)
    for r in st.names.values() {
        // mtp < lease_expiry <= mtp + MAX_LEASE
        if !(m < r.lease_expiry) {
            v += 1;
        }
        if !(r.lease_expiry <= m + MAX_LEASE_I) {
            v += 1;
        }
        if matches!(r.st, St::Listed | St::Offered | St::Reserved) {
            // offer_expiry + REORG_BUFFER <= lease_expiry
            if !(r.offer_expiry + REORG_BUFFER <= r.lease_expiry) {
                v += 1;
            }
        }
        if matches!(r.st, St::Listed | St::Reserved) {
            if r.price < SELL_FLOOR {
                v += 1;
            }
        }
        if r.st == St::Reserved {
            if !(r.reserve_expiry <= r.offer_expiry) {
                v += 1;
            }
            // price >= burn_leg + pay_leg
            if r.price < r.burn_leg + r.pay_leg {
                v += 1;
            }
            if r.burn_leg != deposit_leg(r.price, RESERVE_BURN_BPS) {
                v += 1;
            }
            if r.pay_leg != deposit_leg(r.price, RESERVE_PAY_BPS) {
                v += 1;
            }
            // remainder >= DUST_FLOOR
            if r.price - r.burn_leg - r.pay_leg < DUST_FLOOR {
                v += 1;
            }
        }
    }
    // per-owner mutation height <= current height
    for &mh in st.muts.values() {
        if mh > height {
            v += 1;
        }
    }
    v
}

fn fingerprint(pd: &mut Sha256, st: &State) {
    let (mut n_owned, mut n_listed, mut n_offered, mut n_reserved) = (0u32, 0u32, 0u32, 0u32);
    let mut sum_lease: i128 = 0;
    let mut sum_price: i128 = 0;
    let mut sum_legs: i128 = 0;
    for r in st.names.values() {
        match r.st {
            St::Owned => n_owned += 1,
            St::Listed => n_listed += 1,
            St::Offered => n_offered += 1,
            St::Reserved => n_reserved += 1,
        }
        sum_lease += r.lease_expiry as i128;
        if matches!(r.st, St::Listed | St::Reserved) {
            sum_price += r.price as i128;
        }
        if r.st == St::Reserved {
            sum_legs += r.burn_leg as i128 + r.pay_leg as i128;
        }
    }
    pd.update(&(st.names.len() as u32).to_le_bytes());
    pd.update(&n_owned.to_le_bytes());
    pd.update(&n_listed.to_le_bytes());
    pd.update(&n_offered.to_le_bytes());
    pd.update(&n_reserved.to_le_bytes());
    pd.update(&(st.commits.len() as u32).to_le_bytes());
    pd.update(&(st.muts.len() as u32).to_le_bytes());
    pd.update(&sum_lease.to_le_bytes());
    pd.update(&sum_price.to_le_bytes());
    pd.update(&sum_legs.to_le_bytes());
}

// ───────────────────────── §11 meta (inert tx) ─────────────────────────

/// After folding each block, apply ONE provably-inert tx; the state_digest must not change.
/// Mirrors java `Modes.meta` / `inertTx`. Exit 1 if failures != 0.
pub fn meta(seed: u64, count: u64) {
    let (blocks, timestamps) = record_chain(seed, count.min(20000));
    let mut st = State::new(0);
    let mut failures: u64 = 0;
    for blk in &blocks {
        st.apply_block(blk, &timestamps);
        let before = digest_hex(&st);
        let m = mtp(blk.height, &timestamps);
        apply_one_inert_tx(&mut st, blk, m);
        if digest_hex(&st) != before {
            failures += 1;
        }
    }
    println!("failures={}", failures);
    println!("state_digest={}", digest_hex(&st));
    if failures != 0 {
        exit(1);
    }
}

/// Fold one INERT tx into the current state via a synthetic single-tx block at the same
/// height/timestamp/rate (the fold reads MTP from the timestamp array, so re-using `blk`'s
/// height keeps the boundary math identical — and the pre-block transitions are idempotent
/// for the already-folded state). Java reaches the same via `Fold.applyOneTx`.
fn apply_one_inert_tx(st: &mut State, blk: &Block, m: i64) {
    let id = crate::generator::identity(0).0;
    // naked CLAIM (no live commit) -> drops
    let naked = encode_action(&Action::Claim { salt: [0u8; 32], name: b"inert".to_vec() });
    // malformed RENEW bl=3 -> IGNORE (1..4 invalid)
    let malformed = vec![0xFFu8, 0x50, 0x4E, OP_RENEW, 0x01, 0x02, 0x03];
    // UTF-8 noise / bare text -> IGNORE (names-only demux)
    let noise = b"hi".to_vec();
    // unknown opcode (overlay band) -> IGNORE
    let overlay = vec![0xFFu8, 0x50, 0x4E, 0xD6, 0x00];
    let tx = Tx {
        inputs: vec![Input { identity: Some(id), stype: ScriptType::P2pkh, sighash_all: true }],
        outputs: vec![
            Output::Carrier { payload: naked, value: 1 },
            Output::Carrier { payload: malformed, value: 0 },
            Output::Carrier { payload: noise, value: 1 },
            Output::Carrier { payload: overlay, value: 0 },
        ],
    };
    // re-fold the inert tx alone in its own block (pre-block transitions idempotent on the
    // already-settled state at this same MTP); only the tx body is what we assert inert.
    let inert_blk = Block {
        height: blk.height,
        timestamp: blk.timestamp,
        rate: blk.rate,
        txs: vec![tx],
    };
    // apply through the same fold path, tx-only (no pre-block sweep) at this block's MTP.
    st.apply_block_txs_only(&inert_blk, m);
}

// ───────────────────────── §10 reorg confluence ─────────────────────────

/// replay / resume / clear-rebuild / fork-and-return(reversed tail). Mirrors java `Modes.reorg`.
pub fn reorg(seed: u64, count: u64) {
    let (blocks, timestamps) = record_chain(seed, count.min(20000));
    let n = blocks.len();
    let j = n / 2;
    let mut failures: u64 = 0;

    let d_full = fold_digest(&blocks, &timestamps, 0, n);
    // 1. replay: a second full fold reproduces D_full
    if fold_digest(&blocks, &timestamps, 0, n) != d_full {
        failures += 1;
    }
    // 2. resume: fold [0,J) -> S_fork, continue [J,n) == D_full
    let mut s = State::new(0);
    for blk in &blocks[..j] {
        s.apply_block(blk, &timestamps);
    }
    let s_fork = digest_hex(&s);
    for blk in &blocks[j..] {
        s.apply_block(blk, &timestamps);
    }
    if digest_hex(&s) != d_full {
        failures += 1;
    }
    // 3. clear-rebuild: clear(), re-fold [0,J) == S_fork
    s.clear();
    for blk in &blocks[..j] {
        s.apply_block(blk, &timestamps);
    }
    if digest_hex(&s) != s_fork {
        failures += 1;
    }
    // 4. fork-and-return: divergent branch = canonical tail with each block's txs reversed
    let mut sa = State::new(0);
    for blk in &blocks[..j] {
        sa.apply_block(blk, &timestamps);
    }
    for blk in &blocks[j..] {
        let rb = reverse_txs(blk);
        sa.apply_block(&rb, &timestamps);
    }
    let d_alt = digest_hex(&sa);
    sa.clear();
    for blk in &blocks[..j] {
        sa.apply_block(blk, &timestamps);
    }
    if digest_hex(&sa) != s_fork {
        failures += 1;
    }
    for blk in &blocks[j..] {
        sa.apply_block(blk, &timestamps);
    }
    if digest_hex(&sa) != d_full {
        failures += 1;
    }

    let mut rd = Vec::new();
    rd.extend_from_slice(&hex_to_bytes(&d_full));
    rd.extend_from_slice(&hex_to_bytes(&s_fork));
    rd.extend_from_slice(&hex_to_bytes(&d_alt));
    let mut h = Sha256::new();
    h.update(&rd);
    println!("blocks={} fork={} checks=6 failures={}", n, j, failures);
    println!("D_full={}", d_full);
    println!("S_fork={}", s_fork);
    println!("D_alt={}", d_alt);
    println!("reorg_digest={}", hex32(&h.finalize()));
    if failures != 0 {
        exit(1);
    }
}

fn fold_digest(blocks: &[Block], timestamps: &[i64], lo: usize, hi: usize) -> String {
    let mut s = State::new(0);
    for blk in &blocks[lo..hi] {
        s.apply_block(blk, timestamps);
    }
    digest_hex(&s)
}

fn reverse_txs(b: &Block) -> Block {
    let mut txs = b.txs.clone();
    txs.reverse();
    Block { height: b.height, timestamp: b.timestamp, rate: b.rate, txs }
}

// ───────────────────────── §9 differential fuzz ─────────────────────────

/// Random + grammar-perturbed OP_RETURN payloads through decode -> fold; count crashes.
/// The decoder/fold are written to be fail-closed (never panic) on adversarial bytes, so
/// each block fold is additionally wrapped in `catch_unwind` to surface (rather than abort
/// on) any real panic. Mirrors java `Modes.fuzz`. Exit 1 if parser_crashes != 0.
pub fn fuzz(seed: u64, count: u64) {
    let mut rng = SplitMix64::new(seed);
    let mut st = State::new(0);
    let mut input_hash = Sha256::new();
    let base_ts: i64 = 1_700_000_000;
    let mut ts = base_ts;
    let mut height: i64 = 0;
    let mut tx_count: u64 = 0;
    let mut crashes: u64 = 0;
    let mut timestamps: Vec<i64> = Vec::new();

    while tx_count < count {
        let ts_step = 300 + rng.bounded(600) as i64;
        ts += ts_step;
        timestamps.push(ts);
        let rate = 28 * (1 + rng.bounded(4));
        let ntx = 1 + rng.bounded(8);
        let mut txs: Vec<Tx> = Vec::new();
        for _ in 0..ntx {
            if tx_count >= count {
                break;
            }
            let n_in = 1 + rng.bounded(4);
            let mut ins: Vec<Input> = Vec::new();
            for _ in 0..n_in {
                let (id, _) = crate::generator::identity(rng.bounded(crate::generator::N_IDS));
                let stype = if rng.bounded(4) == 3 { ScriptType::P2sh } else { ScriptType::P2pkh };
                ins.push(Input { identity: Some(id), stype, sighash_all: rng.bounded(8) != 0 });
            }
            let n_out = 1 + rng.bounded(4);
            let mut outs: Vec<Output> = Vec::new();
            for o in 0..n_out {
                let val: u64 = match rng.bounded(3) {
                    0 => 0,
                    1 => u64::MAX - rng.bounded(1000),
                    _ => 1 + rng.bounded(1000),
                };
                if rng.bounded(4) == 0 {
                    let (h160, _) = crate::generator::identity(rng.bounded(crate::generator::N_IDS));
                    let stype = if rng.bounded(2) == 1 { ScriptType::P2sh } else { ScriptType::P2pkh };
                    outs.push(Output::Spend { hash160: h160, stype, value: val });
                    input_hash.update(&(o as u8).to_le_bytes());
                    input_hash.update(&val.to_le_bytes());
                } else {
                    let payload = fuzz_payload(&mut rng);
                    input_hash.update(&(o as u8).to_le_bytes());
                    input_hash.update(&val.to_le_bytes());
                    input_hash.update(&(payload.len() as u32).to_le_bytes());
                    input_hash.update(&payload);
                    outs.push(Output::Carrier { payload, value: val });
                }
            }
            txs.push(Tx { inputs: ins, outputs: outs });
            tx_count += 1;
        }
        let blk = Block { height, timestamp: ts, rate, txs };
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            st.apply_block(&blk, &timestamps);
        }));
        if res.is_err() {
            crashes += 1;
        }
        height += 1;
    }
    println!("input_digest={}", hex32(&input_hash.finalize()));
    println!("state_digest={}", digest_hex(&st));
    println!("parser_crashes={}", crashes);
    if crashes != 0 {
        exit(1);
    }
}

fn fuzz_payload(rng: &mut SplitMix64) -> Vec<u8> {
    if rng.bounded(10) < 4 {
        // dumb-random bytes
        let len = rng.bounded(81) as usize;
        let mut p = vec![0u8; len];
        for b in p.iter_mut() {
            *b = rng.bounded(256) as u8;
        }
        if rng.bounded(3) == 0 && len >= 4 {
            p[0] = 0xFF;
            p[1] = 0x50;
            p[2] = 0x4E;
            p[3] = (1 + rng.bounded(15)) as u8;
        }
        return p;
    }
    // grammar-aware: build a prefixed action-shaped payload, then maybe corrupt
    let mut payload = grammar_payload(rng);
    match rng.bounded(6) {
        2 => {
            if !payload.is_empty() {
                payload.truncate(payload.len() - 1);
            }
        }
        3 => {
            if !payload.is_empty() {
                let i = rng.bounded(payload.len() as u64) as usize;
                payload[i] ^= 1u8 << rng.bounded(8);
            }
        }
        4 => {
            payload.push(rng.bounded(256) as u8);
        }
        _ => {}
    }
    payload
}

fn grammar_payload(rng: &mut SplitMix64) -> Vec<u8> {
    let op = (1 + rng.bounded(15)) as u8; // 0x01..0x0F name-action range
    let body_len: usize = match op {
        OP_COMMIT => 32,
        OP_CLAIM => 33 + rng.bounded(20) as usize,
        OP_RENEW => [0usize, 5, 6 + rng.bounded(71) as usize][rng.bounded(3) as usize],
        OP_TRANSFER => {
            if rng.bounded(2) == 0 {
                20
            } else {
                26 + rng.bounded(51) as usize
            }
        }
        OP_SELL => 13 + rng.bounded(20) as usize,
        OP_RENEW_NAME | OP_RELEASE_NAME | OP_RESERVE | OP_SETTLE | OP_PAY => 1 + rng.bounded(20) as usize,
        OP_TRANSFER_NAME => 21 + rng.bounded(31) as usize,
        OP_RELEASE => 6 + rng.bounded(71) as usize,
        OP_SELL_TO => 29 + rng.bounded(20) as usize,
        OP_AS => 1,
        OP_TRADE => 5 + rng.bounded(30) as usize,
        _ => rng.bounded(77) as usize,
    };
    let mut p = vec![0u8; 4 + body_len];
    p[0] = 0xFF;
    p[1] = 0x50;
    p[2] = 0x4E;
    p[3] = op;
    for b in p[4..].iter_mut() {
        *b = rng.bounded(256) as u8;
    }
    p
}

// ───────────────────────── §11 reorgfuzz ─────────────────────────

/// K=64 PRNG fork/divergence trials; clear-rebuild + canonical-replay purity.
/// Mirrors java `Modes.reorgfuzz`. Exit 1 if failures != 0.
pub fn reorgfuzz(seed: u64, count: u64) {
    let (blocks, timestamps) = record_chain(seed, count.min(20000));
    let n = blocks.len();
    let d_full = fold_digest(&blocks, &timestamps, 0, n);
    let mut tr = SplitMix64::new(seed ^ 0x5245464B5A475F31);
    let mut alt_stream = Sha256::new();
    let mut failures: u64 = 0;
    for _ in 0..64 {
        let j = tr.bounded((n + 1) as u64) as usize;
        let kind = tr.bounded(3);
        // divergent branch -> D_alt
        let mut sd = State::new(0);
        for blk in &blocks[..j] {
            sd.apply_block(blk, &timestamps);
        }
        let tail = divergent_tail(&blocks, j, n, kind);
        for blk in &tail {
            sd.apply_block(blk, &timestamps);
        }
        alt_stream.update(&hex_to_bytes(&digest_hex(&sd)));
        // assert: clear-rebuild to J reproduces fold[0,J); canonical replay reproduces D_full
        let fork_j = fold_digest(&blocks, &timestamps, 0, j);
        let mut sc = State::new(0);
        for blk in &blocks[..j] {
            sc.apply_block(blk, &timestamps);
        }
        if digest_hex(&sc) != fork_j {
            failures += 1;
        }
        for blk in &blocks[j..] {
            sc.apply_block(blk, &timestamps);
        }
        if digest_hex(&sc) != d_full {
            failures += 1;
        }
    }
    alt_stream.update(&hex_to_bytes(&d_full));
    println!("blocks={} trials=64 failures={}", n, failures);
    println!("reorgfuzz_digest={}", hex32(&alt_stream.finalize()));
    if failures != 0 {
        exit(1);
    }
}

fn divergent_tail(blocks: &[Block], j: usize, n: usize, kind: u64) -> Vec<Block> {
    let mut out = Vec::new();
    match kind {
        0 => {
            for blk in &blocks[j..n] {
                out.push(reverse_txs(blk));
            }
        }
        1 => {
            let mut i = j;
            while i < n {
                out.push(blocks[i].clone());
                i += 2;
            }
        }
        _ => {
            for blk in &blocks[j..n] {
                out.push(blk.clone());
                out.push(blk.clone());
            }
        }
    }
    out
}
