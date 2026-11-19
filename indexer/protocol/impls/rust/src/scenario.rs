//! Directed conformance vectors (`sm scenario`) — mirrors `impls/c cmd_scenario`
//! construction-for-construction. Each vector builds a deterministic, named state
//! and emits `name <digest>`; u64 vectors (oracle/MTP) emit `name <decimal>`. The
//! rolling `combined` hash (SHA-256 over the concatenated 32-byte digests / 8-byte
//! LE u64s, in order) is the single-line cross-language check.
//!
//! MTP control: the C reference feeds the fold an explicit per-block MTP
//! (`sm_begin_block(s, h, mtp, rate)`). This impl derives MTP from the timestamp
//! array, so each block here is applied with `prev_timestamps = [mtp; height]` —
//! every predecessor equal ⇒ the median is exactly `mtp` for any height ≥ 1.
//!
//! tx_index control: this impl numbers txs by their position in the block's tx
//! vec, so vectors that pin non-contiguous tx_index values (42) pad the block with
//! inert empty txs. The state digest orders commits canonically, so the differing
//! insertion order is invisible.

use crate::decode::{Action, BitmapSel, RenewMode};
use crate::digest::{hex32, state_digest};
use crate::encode::encode_action;
use crate::fold::State;
use crate::model::{Block, Input, Output, Tx};
use crate::oracle::{fee_per_byte, mtp, oracle_rate};
use crate::sha256::sha256;
use crate::types::*;

/// rate = 28 makes the burn equal the number of days: T = B·LEASE_QUANTUM/(rate·BILLING_UNIT) = B.
const RATE_DAYS: u64 = 28;

fn h160(tag: u8) -> Hash160 {
    let mut h = [0u8; 20];
    h[0] = tag;
    h[19] = tag;
    h
}

fn inp(tag: u8) -> Input {
    Input { identity: Some(h160(tag)), stype: ScriptType::P2pkh, sighash_all: true }
}

/// One P2PKH SIGHASH_ALL input (the C `tx1`).
fn tx1(tag: u8, outputs: Vec<Output>) -> Tx {
    Tx { inputs: vec![inp(tag)], outputs }
}

/// Two P2PKH SIGHASH_ALL inputs (the C `tx2`).
fn tx2(t0: u8, t1: u8, outputs: Vec<Output>) -> Tx {
    Tx { inputs: vec![inp(t0), inp(t1)], outputs }
}

/// Inert padding tx — no inputs, no outputs (tx_index placeholder, vector 42).
fn tx_pad() -> Tx {
    Tx { inputs: Vec::new(), outputs: Vec::new() }
}

fn car(a: &Action, value: u64) -> Output {
    Output::Carrier { payload: encode_action(a), value }
}

fn spend(dest: &Hash160, value: u64) -> Output {
    Output::Spend { hash160: *dest, stype: ScriptType::P2pkh, value }
}

fn commitment_of(salt: &[u8; 32], name: &[u8], author: &Hash160) -> [u8; 32] {
    let mut pre = Vec::with_capacity(32 + name.len() + 20);
    pre.extend_from_slice(salt);
    pre.extend_from_slice(name);
    pre.extend_from_slice(author);
    sha256(&pre)
}

fn mk_commit(name: &[u8], author: &Hash160, salt0: u8) -> Action {
    Action::Commit { commitment: commitment_of(&[salt0; 32], name, author) }
}

fn mk_claim(name: &[u8], salt0: u8) -> Action {
    Action::Claim { salt: [salt0; 32], name: name.to_vec() }
}

/// Scenario harness: the C `sm_begin_block(h, mtp, RATE_DAYS)` + per-tx applies,
/// expressed as one block with a constant-timestamp predecessor array.
struct Sc {
    st: State,
}

impl Sc {
    fn new() -> Self {
        Sc { st: State::new(0) }
    }
    fn block(&mut self, height: i64, block_mtp: i64, txs: Vec<Tx>) {
        let ts = vec![block_mtp; height as usize];
        debug_assert_eq!(mtp(height, &ts), block_mtp);
        let blk = Block { height, timestamp: block_mtp, rate: RATE_DAYS, txs };
        self.st.apply_block(&blk, &ts);
    }
}

/// Commit `name`(author=tag, salt) at block `ch`, then CLAIM `days` at block `kh`.
#[allow(clippy::too_many_arguments)]
fn commit_then_claim(sc: &mut Sc, tag: u8, nm: &[u8], salt0: u8, days: u64, cmtp: i64, ch: i64, kmtp: i64, kh: i64) {
    let author = h160(tag);
    sc.block(ch, cmtp, vec![tx1(tag, vec![car(&mk_commit(nm, &author, salt0), 0)])]);
    sc.block(kh, kmtp, vec![tx1(tag, vec![car(&mk_claim(nm, salt0), days)])]);
}

/// Mint `name` to `tag` with a `days` lease, leaving the fold at the claim's block (C `minted`).
fn minted(tag: u8, name: &[u8], days: u64, claim_mtp: i64) -> Sc {
    let mut sc = Sc::new();
    let author = h160(tag);
    sc.block(10, claim_mtp - 100, vec![tx1(tag, vec![car(&mk_commit(name, &author, 0x33), 0)])]);
    sc.block(11, claim_mtp, vec![tx1(tag, vec![car(&mk_claim(name, 0x33), days)])]);
    sc
}

/// Mint `aaa`→A and `bbb`→B, leaving the fold at height 11 (C `two_names`).
fn two_names() -> Sc {
    let a = h160(0xAA);
    let b = h160(0xBB);
    let mut sc = Sc::new();
    sc.block(10, 1000, vec![
        tx1(0xAA, vec![car(&mk_commit(b"aaa", &a, 0x01), 0)]),
        tx1(0xBB, vec![car(&mk_commit(b"bbb", &b, 0x02), 0)]),
    ]);
    sc.block(11, 1500, vec![
        tx1(0xAA, vec![car(&mk_claim(b"aaa", 0x01), 30)]),
        tx1(0xBB, vec![car(&mk_claim(b"bbb", 0x02), 30)]),
    ]);
    sc
}

fn emit_state(comb: &mut Vec<u8>, name: &str, sc: &Sc) {
    let d = state_digest(&sc.st);
    println!("{} {}", name, hex32(&d));
    comb.extend_from_slice(&d);
}

fn emit_u64(comb: &mut Vec<u8>, name: &str, v: u64) {
    println!("{} {}", name, v);
    comb.extend_from_slice(&v.to_le_bytes());
}

pub fn run() -> i32 {
    let mut comb: Vec<u8> = Vec::new();
    let a = h160(0xAA);
    let b = h160(0xBB);
    let cc = h160(0xCC);

    // 01: empty state.
    {
        let sc = Sc::new();
        emit_state(&mut comb, "01_empty", &sc);
    }

    // 02: plain commit → claim.
    {
        let mut sc = Sc::new();
        commit_then_claim(&mut sc, 0xAA, b"bob", 0x11, 10, 1000, 10, 1500, 11);
        emit_state(&mut comb, "02_commit_claim", &sc);
    }

    // 03: naked claim (no commit) → drop.
    {
        let mut sc = Sc::new();
        sc.block(11, 1500, vec![tx1(0xAA, vec![car(&mk_claim(b"bob", 0x11), 10)])]);
        emit_state(&mut comb, "03_naked_claim_drop", &sc);
    }

    // 04: same-tx commit too shallow → claim drops, commit still recorded.
    {
        let mut sc = Sc::new();
        sc.block(11, 1500, vec![tx1(0xAA, vec![
            car(&mk_commit(b"bob", &a, 0x11), 0),
            car(&mk_claim(b"bob", 0x11), 10),
        ])]);
        emit_state(&mut comb, "04_shallow_commit_drop", &sc);
    }

    // 05/06: priority — lower commit_height (A@10) wins in BOTH claim orderings.
    for order in 0..2 {
        let mut sc = Sc::new();
        sc.block(10, 1000, vec![tx1(0xAA, vec![car(&mk_commit(b"bob", &a, 0x11), 0)])]);
        sc.block(12, 1100, vec![tx1(0xBB, vec![car(&mk_commit(b"bob", &b, 0x22), 0)])]);
        let ka = tx1(0xAA, vec![car(&mk_claim(b"bob", 0x11), 10)]);
        let kb = tx1(0xBB, vec![car(&mk_claim(b"bob", 0x22), 10)]);
        let txs = if order == 0 { vec![kb, ka] } else { vec![ka, kb] };
        sc.block(20, 1200, txs);
        emit_state(&mut comb, if order == 0 { "05_priority_b_first" } else { "06_priority_a_first" }, &sc);
    }

    // 07: commitment-copy — B reposts A's commitment bytes; B's claim drops, A's mints.
    {
        let mut sc = Sc::new();
        let ca = mk_commit(b"bob", &a, 0x33); // A-bound commitment
        sc.block(10, 1000, vec![
            tx1(0xAA, vec![car(&ca, 0)]),
            tx1(0xBB, vec![car(&ca, 0)]), // B copies the commitment bytes
        ]);
        sc.block(11, 1100, vec![
            tx1(0xBB, vec![car(&mk_claim(b"bob", 0x33), 10)]), // B can't satisfy → drop
            tx1(0xAA, vec![car(&mk_claim(b"bob", 0x33), 10)]), // A wins
        ]);
        emit_state(&mut comb, "07_commitment_copy", &sc);
    }

    // 08: lease lapse at MTP == expiry (exclusive bound).
    {
        let mut sc = minted(0xAA, b"bob", 10, 1500); // expiry 865500
        sc.block(12, 865500, vec![]);
        emit_state(&mut comb, "08_lease_lapse", &sc);
    }

    // 09: renew-all stacks days.
    {
        let mut sc = minted(0xAA, b"bob", 10, 1500);
        sc.block(12, 1600, vec![tx1(0xAA, vec![car(&Action::Renew { mode: RenewMode::All }, 5)])]);
        emit_state(&mut comb, "09_renew_stack", &sc);
    }

    // 10: water-fill even split — 3 names, renew-all buys 30 name-days → +10 each.
    {
        let mut sc = Sc::new();
        let nm: [&[u8]; 3] = [b"a", b"b", b"c"];
        sc.block(10, 1000, (0..3).map(|i| tx1(0xAA, vec![car(&mk_commit(nm[i], &a, 0x40 + i as u8), 0)])).collect());
        sc.block(11, 1100, (0..3).map(|i| tx1(0xAA, vec![car(&mk_claim(nm[i], 0x40 + i as u8), 1)])).collect());
        sc.block(12, 1200, vec![tx1(0xAA, vec![car(&Action::Renew { mode: RenewMode::All }, 30)])]);
        emit_state(&mut comb, "10_waterfill_even", &sc);
    }

    // 11: huge claim burn caps at MAX_LEASE (365d).
    {
        let mut sc = Sc::new();
        commit_then_claim(&mut sc, 0xAA, b"bob", 0x11, 100000, 1000, 10, 1500, 11);
        emit_state(&mut comb, "11_waterfill_maxlease", &sc);
    }

    // 12: transfer-all gift.
    {
        let mut sc = minted(0xAA, b"bob", 10, 1500);
        sc.block(12, 1600, vec![tx1(0xAA, vec![car(&Action::Transfer { target: b, sel: None }, 0)])]);
        emit_state(&mut comb, "12_transfer_gift", &sc);
    }

    // 13: selective RELEASE (anchor 11, bit 0).
    {
        let mut sc = minted(0xAA, b"bob", 10, 1500);
        sc.block(12, 1600, vec![tx1(0xAA, vec![car(&Action::Release { anchor: 11, flags: vec![0x01] }, 0)])]);
        emit_state(&mut comb, "13_release", &sc);
    }

    // 14: full open-market cycle SELL → RESERVE → SETTLE.
    {
        let mut sc = minted(0xAA, b"w", 300, 1500);
        sc.block(12, 1600, vec![tx1(0xAA, vec![car(&Action::Sell { price: 20000, window: 50000, name: b"w".to_vec() }, 0)])]);
        sc.block(13, 1700, vec![tx1(0xBB, vec![car(&Action::Reserve { name: b"w".to_vec() }, 100), spend(&a, 100)])]);
        sc.block(14, 1800, vec![tx1(0xBB, vec![car(&Action::Settle { name: b"w".to_vec() }, 0), spend(&a, 19800)])]);
        emit_state(&mut comb, "14_market_full", &sc);
    }

    // 15: RESERVE burn leg short (99 < 100) → drop.
    {
        let mut sc = minted(0xAA, b"w", 300, 1500);
        sc.block(12, 1600, vec![tx1(0xAA, vec![car(&Action::Sell { price: 20000, window: 50000, name: b"w".to_vec() }, 0)])]);
        sc.block(13, 1700, vec![tx1(0xBB, vec![car(&Action::Reserve { name: b"w".to_vec() }, 99), spend(&a, 100)])]);
        emit_state(&mut comb, "15_reserve_burn_short", &sc);
    }

    // 16: pay leg is NOT summed across outputs (two 60s ≠ one 100) → drop.
    {
        let mut sc = minted(0xAA, b"w", 300, 1500);
        sc.block(12, 1600, vec![tx1(0xAA, vec![car(&Action::Sell { price: 20000, window: 50000, name: b"w".to_vec() }, 0)])]);
        sc.block(13, 1700, vec![tx1(0xBB, vec![car(&Action::Reserve { name: b"w".to_vec() }, 100), spend(&a, 60), spend(&a, 60)])]);
        emit_state(&mut comb, "16_reserve_pay_summed", &sc);
    }

    // 17: reserve near offer end → reserve_expiry clamps to offer_expiry.
    {
        let mut sc = minted(0xAA, b"w", 300, 1500);
        sc.block(12, 1600, vec![tx1(0xAA, vec![car(&Action::Sell { price: 20000, window: 0, name: b"w".to_vec() }, 0)])]); // window default 18000 → offer_expiry 19600
        sc.block(13, 5000, vec![tx1(0xBB, vec![car(&Action::Reserve { name: b"w".to_vec() }, 100), spend(&a, 100)])]); // 5000+18000>19600 → clamp
        emit_state(&mut comb, "17_reserve_clamp", &sc);
    }

    // 18: SELL price below 3·DUST → reject.
    {
        let mut sc = minted(0xAA, b"w", 300, 1500);
        sc.block(12, 1600, vec![tx1(0xAA, vec![car(&Action::Sell { price: 2, window: 0, name: b"w".to_vec() }, 0)])]);
        emit_state(&mut comb, "18_sell_price_floor", &sc);
    }

    // 19: SELL whose window overruns the lease tail → reject.
    {
        let mut sc = minted(0xAA, b"w", 1, 1500); // short tail
        sc.block(12, 65000, vec![tx1(0xAA, vec![car(&Action::Sell { price: 20000, window: 0, name: b"w".to_vec() }, 0)])]);
        emit_state(&mut comb, "19_sell_window_overflow", &sc);
    }

    // 20: directed SELL_TO/PAY — stranger drops, named buyer conveys.
    {
        let mut sc = minted(0xAA, b"w", 300, 1500);
        sc.block(12, 1600, vec![tx1(0xAA, vec![car(&Action::SellTo { price: 5000, buyer: b, name: b"w".to_vec() }, 0)])]);
        sc.block(13, 1700, vec![
            tx1(0xCC, vec![car(&Action::Pay { name: b"w".to_vec() }, 0), spend(&a, 5000)]), // stranger → drop
            tx1(0xBB, vec![car(&Action::Pay { name: b"w".to_vec() }, 0), spend(&a, 5000)]), // buyer → owns
        ]);
        emit_state(&mut comb, "20_directed_pay", &sc);
    }

    // 21: 2^64−1 price — the 128-bit deposit legs must be exact (a 64-bit impl wraps).
    {
        let mut sc = minted(0xAA, b"w", 300, 1500);
        sc.block(12, 1600, vec![tx1(0xAA, vec![car(&Action::Sell { price: u64::MAX, window: 50000, name: b"w".to_vec() }, 0)])]);
        let leg = ((u64::MAX as u128) * 50 / 10000) as u64;
        sc.block(13, 1700, vec![tx1(0xBB, vec![car(&Action::Reserve { name: b"w".to_vec() }, leg), spend(&a, leg)])]);
        emit_state(&mut comb, "21_deposit_2pow64", &sc);
    }

    // 22: AS attribution — claim attributed to vin[1]=B (matches B's commit).
    {
        let mut sc = Sc::new();
        sc.block(10, 1000, vec![tx1(0xBB, vec![car(&mk_commit(b"bob", &b, 0x55), 0)])]);
        sc.block(11, 1500, vec![tx2(0xAA, 0xBB, vec![
            car(&Action::As { index: 1 }, 0),
            car(&mk_claim(b"bob", 0x55), 10),
        ])]);
        emit_state(&mut comb, "22_as_attribution", &sc);
    }

    // 23: AS to a non-SIGHASH_ALL input → segment drops.
    {
        let mut sc = Sc::new();
        sc.block(10, 1000, vec![tx1(0xBB, vec![car(&mk_commit(b"bob", &b, 0x55), 0)])]);
        let mut t = tx2(0xAA, 0xBB, vec![
            car(&Action::As { index: 1 }, 0),
            car(&mk_claim(b"bob", 0x55), 10),
        ]);
        t.inputs[1].sighash_all = false;
        sc.block(11, 1500, vec![t]);
        emit_state(&mut comb, "23_as_oob_drop", &sc);
    }

    // 24: TRADE happy-path swap aaa↔bbb.
    {
        let mut sc = two_names();
        sc.block(12, 1600, vec![tx2(0xAA, 0xBB, vec![
            car(&Action::Trade { idx_a: 0, idx_b: 1, name_a: b"aaa".to_vec(), name_b: b"bbb".to_vec() }, 0),
        ])]);
        emit_state(&mut comb, "24_trade_swap", &sc);
    }

    // 25: anti-rug — aaa moved same-block before the trade → whole-op drop.
    {
        let mut sc = two_names();
        sc.block(12, 1600, vec![
            tx1(0xAA, vec![car(&Action::Transfer { target: cc, sel: None }, 0)]), // aaa→C before the trade
            tx2(0xAA, 0xBB, vec![car(&Action::Trade { idx_a: 0, idx_b: 1, name_a: b"aaa".to_vec(), name_b: b"bbb".to_vec() }, 0)]),
        ]);
        emit_state(&mut comb, "25_trade_rug_before", &sc);
    }

    // 29–31: fee-oracle / MTP scalars (§3.4, §5).
    {
        let sub: u64 = 1_000_000_000_000;
        let cb: [i64; 5] = [1_000_000_200_000, 1_000_000_400_000, 999_999_999_950, 1_000_001_000_000, 1_000_000_600_000];
        let w: Vec<u64> = cb.iter().map(|&c| fee_per_byte(c as u64, sub, 1000)).collect();
        emit_u64(&mut comb, "29_oracle_rate", oracle_rate(&w)); // |P|=4 < 1000 → DUST_FLOOR = 1
    }
    {
        let sub: u64 = 1_000_000_000_000;
        let w: Vec<u64> = (0..3).map(|_| fee_per_byte(0, sub, 1000)).collect(); // all under-claim
        emit_u64(&mut comb, "30_oracle_floor", oracle_rate(&w));
    }
    {
        let ts: [i64; 11] = [100, 50, 200, 30, 150, 80, 220, 10, 175, 60, 190];
        emit_u64(&mut comb, "31_mtp_median", mtp(11, &ts) as u64); // median of 11
    }

    // 32: water-fill T < count — first T names (ascending-lex) get +1 day, the rest none.
    {
        let mut sc = Sc::new();
        let nm: [&[u8]; 3] = [b"a", b"b", b"c"];
        sc.block(10, 1000, (0..3).map(|i| tx1(0xAA, vec![car(&mk_commit(nm[i], &a, 0x50 + i as u8), 0)])).collect());
        sc.block(11, 1100, (0..3).map(|i| tx1(0xAA, vec![car(&mk_claim(nm[i], 0x50 + i as u8), 1)])).collect());
        sc.block(12, 1200, vec![tx1(0xAA, vec![car(&Action::Renew { mode: RenewMode::All }, 2)])]); // T=2 over 3 → a,b +1d, c none
        emit_state(&mut comb, "32_waterfill_floor", &sc);
    }

    // 33: every targeted name hits MAX_LEASE with T remaining → surplus forfeited.
    {
        let mut sc = Sc::new();
        let nm: [&[u8]; 2] = [b"a", b"b"];
        sc.block(10, 1000, (0..2).map(|i| tx1(0xAA, vec![car(&mk_commit(nm[i], &a, 0x60 + i as u8), 0)])).collect());
        sc.block(11, 1100, (0..2).map(|i| tx1(0xAA, vec![car(&mk_claim(nm[i], 0x60 + i as u8), 360)])).collect());
        sc.block(12, 1100, vec![tx1(0xAA, vec![car(&Action::Renew { mode: RenewMode::All }, 100000)])]); // huge → both cap, forfeit
        emit_state(&mut comb, "33_waterfill_allcap_forfeit", &sc);
    }

    // 34: same-block lapse-and-reclaim vs a reorg-restored RENEW.
    {
        let mut sc = minted(0xAA, b"bob", 10, 1500); // expiry 865500
        sc.block(12, 860000, vec![tx1(0xBB, vec![car(&mk_commit(b"bob", &b, 0x44), 0)])]);
        sc.block(13, 865500, vec![tx1(0xBB, vec![car(&mk_claim(b"bob", 0x44), 10)])]); // lapse then B mints
        emit_state(&mut comb, "34a_reorg_lapse_reclaim", &sc);
    }
    {
        let mut sc = minted(0xAA, b"bob", 10, 1500);
        sc.block(12, 860000, vec![
            tx1(0xBB, vec![car(&mk_commit(b"bob", &b, 0x44), 0)]),
            tx1(0xAA, vec![car(&Action::Renew { mode: RenewMode::All }, 10)]), // A renews → bob survives
        ]);
        sc.block(13, 865500, vec![tx1(0xBB, vec![car(&mk_claim(b"bob", 0x44), 10)])]); // bob owned → drop
        emit_state(&mut comb, "34b_reorg_renew_blocks_reclaim", &sc);
    }

    // 35: SETTLE un-confirmed by a reorg — reserve lapses back to LISTED vs settle confirms.
    {
        let mut sc = minted(0xAA, b"w", 300, 1500);
        sc.block(12, 1600, vec![tx1(0xAA, vec![car(&Action::Sell { price: 20000, window: 50000, name: b"w".to_vec() }, 0)])]);
        sc.block(13, 1700, vec![tx1(0xBB, vec![car(&Action::Reserve { name: b"w".to_vec() }, 100), spend(&a, 100)])]);
        sc.block(14, 20000, vec![]); // MTP past reserve_expiry (19700) → revert to listing
        emit_state(&mut comb, "35a_settle_dropped_relisted", &sc);
    }
    {
        let mut sc = minted(0xAA, b"w", 300, 1500);
        sc.block(12, 1600, vec![tx1(0xAA, vec![car(&Action::Sell { price: 20000, window: 50000, name: b"w".to_vec() }, 0)])]);
        sc.block(13, 1700, vec![tx1(0xBB, vec![car(&Action::Reserve { name: b"w".to_vec() }, 100), spend(&a, 100)])]);
        sc.block(14, 1800, vec![tx1(0xBB, vec![car(&Action::Settle { name: b"w".to_vec() }, 0), spend(&a, 19800)])]);
        emit_state(&mut comb, "35b_settle_confirmed", &sc);
    }

    // 36: MTP boundary — lease_expiry is EXCLUSIVE: expiry−1 owned, expiry lapsed.
    {
        let mut sc = minted(0xAA, b"bob", 10, 1500);
        sc.block(12, 865499, vec![]);
        emit_state(&mut comb, "36a_mtp_below_owned", &sc);
    }
    {
        let mut sc = minted(0xAA, b"bob", 10, 1500);
        sc.block(12, 865500, vec![]);
        emit_state(&mut comb, "36b_mtp_at_lapsed", &sc);
    }

    // 38: same-block RENEW-vs-CLAIM race at the exact lapse tie (pre-block lapse first).
    {
        let mut sc = Sc::new();
        sc.block(10, 1000, vec![
            tx1(0xAA, vec![car(&mk_commit(b"bob", &a, 0x33), 0)]),
            tx1(0xAA, vec![car(&mk_commit(b"keep", &a, 0x34), 0)]),
        ]);
        sc.block(11, 1500, vec![
            tx1(0xAA, vec![car(&mk_claim(b"bob", 0x33), 10)]),   // bob expiry 865500
            tx1(0xAA, vec![car(&mk_claim(b"keep", 0x34), 300)]), // keep long-lived
        ]);
        sc.block(12, 860000, vec![tx1(0xBB, vec![car(&mk_commit(b"bob", &b, 0x44), 0)])]); // hunter commits
        sc.block(13, 865500, vec![
            tx1(0xAA, vec![car(&Action::Renew { mode: RenewMode::All }, 5)]), // renews `keep` only
            tx1(0xBB, vec![car(&mk_claim(b"bob", 0x44), 10)]),                // hunter mints bob
        ]);
        emit_state(&mut comb, "38_lapse_renew_vs_claim", &sc);
    }

    // 39: one pre-block tick crossing reserve_expiry AND offer_expiry (cascade to OWNED).
    {
        let mut sc = minted(0xAA, b"w", 300, 1500);
        sc.block(12, 1600, vec![tx1(0xAA, vec![car(&Action::Sell { price: 20000, window: 50000, name: b"w".to_vec() }, 0)])]); // offer_expiry 51600
        sc.block(13, 1700, vec![tx1(0xBB, vec![car(&Action::Reserve { name: b"w".to_vec() }, 100), spend(&a, 100)])]); // reserve_expiry 19700
        sc.block(14, 51600, vec![]); // MTP == offer_expiry, > reserve_expiry → both legs fire
        emit_state(&mut comb, "39_preblock_reserve_offer_collapse", &sc);
    }

    // 40: intra-block RESERVE option theft — first buyer wins, loser's SETTLE drops.
    {
        let mut sc = minted(0xAA, b"w", 300, 1500);
        sc.block(12, 1600, vec![tx1(0xAA, vec![car(&Action::Sell { price: 20000, window: 50000, name: b"w".to_vec() }, 0)])]);
        sc.block(13, 1700, vec![
            tx1(0xBB, vec![car(&Action::Reserve { name: b"w".to_vec() }, 100), spend(&a, 100)]),   // B wins the option
            tx1(0xCC, vec![car(&Action::Reserve { name: b"w".to_vec() }, 100), spend(&a, 100)]),   // C loses → drop
            tx1(0xCC, vec![car(&Action::Settle { name: b"w".to_vec() }, 0), spend(&a, 19800)]),    // buyer-mismatch → drop
        ]);
        emit_state(&mut comb, "40_reserve_option_theft", &sc);
    }

    // 41: value-collision in spendable-output matching (consume-once, exact-value, vout order).
    {
        let mut sc = Sc::new();
        sc.block(10, 1000, vec![
            tx1(0xAA, vec![car(&mk_commit(b"x", &a, 0x71), 0)]),
            tx1(0xAA, vec![car(&mk_commit(b"y", &a, 0x72), 0)]),
        ]);
        sc.block(11, 1500, vec![
            tx1(0xAA, vec![car(&mk_claim(b"x", 0x71), 300)]),
            tx1(0xAA, vec![car(&mk_claim(b"y", 0x72), 300)]),
        ]);
        sc.block(12, 1600, vec![
            tx1(0xAA, vec![car(&Action::Sell { price: 1000, window: 50000, name: b"x".to_vec() }, 0)]),  // pay_leg(x) = 5
            tx1(0xAA, vec![car(&Action::Sell { price: 20000, window: 50000, name: b"y".to_vec() }, 0)]), // remainder(y) = 19800
        ]);
        sc.block(13, 1700, vec![tx1(0xBB, vec![car(&Action::Reserve { name: b"y".to_vec() }, 100), spend(&a, 100)])]); // B reserves y
        sc.block(14, 1800, vec![tx1(0xBB, vec![
            car(&Action::Reserve { name: b"x".to_vec() }, 5), // car_value 5 ≥ burn_leg(x)=5
            car(&Action::Settle { name: b"y".to_vec() }, 0),
            spend(&a, 19800), // lower vout = settle remainder
            spend(&a, 5),     // higher vout = reserve pay-leg
        ])]);
        emit_state(&mut comb, "41_vout_value_collision", &sc);
    }

    // 42: CLAIM priority tie-break is the COMMIT's tx_index (B's commit tx_index 2 < A's 5).
    // Inert pad txs pin the non-contiguous tx_index values; the digest orders commits canonically.
    {
        let mut sc = Sc::new();
        sc.block(10, 1000, vec![
            tx_pad(),
            tx_pad(),
            tx1(0xBB, vec![car(&mk_commit(b"bob", &b, 0x82), 0)]), // tx_index 2
            tx_pad(),
            tx_pad(),
            tx1(0xAA, vec![car(&mk_commit(b"bob", &a, 0x81), 0)]), // tx_index 5
        ]);
        sc.block(20, 1500, vec![
            tx1(0xAA, vec![car(&mk_claim(b"bob", 0x81), 10)]), // applied first
            tx1(0xBB, vec![car(&mk_claim(b"bob", 0x82), 10)]), // lower commit tx_index → wins
        ]);
        emit_state(&mut comb, "42_claim_commit_txindex_tiebreak", &sc);
    }

    // 43: escrow movement-lock — a LISTED name rejects TRANSFER/RELEASE/re-SELL/SELL_TO.
    {
        let mut sc = minted(0xAA, b"w", 300, 1500);
        sc.block(12, 1600, vec![tx1(0xAA, vec![car(&Action::Sell { price: 20000, window: 50000, name: b"w".to_vec() }, 0)])]);
        sc.block(13, 1700, vec![
            tx1(0xAA, vec![car(&Action::Transfer { target: b, sel: None }, 0)]),
            tx1(0xAA, vec![car(&Action::Release { anchor: 11, flags: vec![0x01] }, 0)]),
            tx1(0xAA, vec![car(&Action::Sell { price: 30000, window: 50000, name: b"w".to_vec() }, 0)]),
            tx1(0xAA, vec![car(&Action::SellTo { price: 5000, buyer: b, name: b"w".to_vec() }, 0)]),
        ]);
        emit_state(&mut comb, "43_escrow_movement_lock", &sc);
    }

    // 44: anchor-guard reject — bitmap op anchored OLDER than the last set-mutation drops.
    {
        let mut sc = Sc::new();
        sc.block(10, 1000, vec![tx1(0xAA, vec![car(&mk_commit(b"a", &a, 0x91), 0)])]);
        sc.block(11, 1500, vec![
            tx1(0xAA, vec![car(&mk_claim(b"a", 0x91), 30)]),      // lm(A)=11
            tx1(0xAA, vec![car(&mk_commit(b"b", &a, 0x92), 0)]),
        ]);
        sc.block(12, 1600, vec![tx1(0xAA, vec![car(&mk_claim(b"b", 0x92), 30)])]); // lm(A)=12
        sc.block(13, 1700, vec![tx1(0xAA, vec![car(&Action::Release { anchor: 11, flags: vec![0x01] }, 0)])]); // anchor 11 < lm 12 → reject
        emit_state(&mut comb, "44_anchor_guard_reject", &sc);
    }

    // 45: COMMIT_EXPIRY prune — a commit older than 18000s is pruned pre-block; claim drops.
    {
        let mut sc = Sc::new();
        sc.block(10, 1000, vec![tx1(0xAA, vec![car(&mk_commit(b"bob", &a, 0x33), 0)])]);
        sc.block(11, 19001, vec![tx1(0xAA, vec![car(&mk_claim(b"bob", 0x33), 10)])]); // 19001 > 1000+18000 → prune
        emit_state(&mut comb, "45_commit_expiry_prune", &sc);
    }

    // 46: RESERVE burn leg is an inequality — an over-funded burn (150 > 100) still wins.
    {
        let mut sc = minted(0xAA, b"w", 300, 1500);
        sc.block(12, 1600, vec![tx1(0xAA, vec![car(&Action::Sell { price: 20000, window: 50000, name: b"w".to_vec() }, 0)])]);
        sc.block(13, 1700, vec![tx1(0xBB, vec![car(&Action::Reserve { name: b"w".to_vec() }, 150), spend(&a, 100)])]);
        emit_state(&mut comb, "46_reserve_overfunded_burn", &sc);
    }

    // 47: TRADE malformed drops — OOB index, idxA==idxB, nameA==nameB all fail-closed.
    {
        let mut sc = two_names();
        sc.block(12, 1600, vec![
            tx2(0xAA, 0xBB, vec![car(&Action::Trade { idx_a: 0, idx_b: 5, name_a: b"aaa".to_vec(), name_b: b"bbb".to_vec() }, 0)]),
            tx2(0xAA, 0xBB, vec![car(&Action::Trade { idx_a: 0, idx_b: 0, name_a: b"aaa".to_vec(), name_b: b"bbb".to_vec() }, 0)]),
            tx2(0xAA, 0xBB, vec![car(&Action::Trade { idx_a: 0, idx_b: 1, name_a: b"aaa".to_vec(), name_b: b"aaa".to_vec() }, 0)]),
        ]);
        emit_state(&mut comb, "47_trade_malformed_drops", &sc);
    }

    // 48: selective TRANSFER — bits {0,2} of A's sorted set {a,b,c} move to B; b stays.
    {
        let mut sc = Sc::new();
        let nm: [&[u8]; 3] = [b"a", b"b", b"c"];
        sc.block(10, 1000, (0..3).map(|i| tx1(0xAA, vec![car(&mk_commit(nm[i], &a, 0xA1 + i as u8), 0)])).collect());
        sc.block(11, 1500, (0..3).map(|i| tx1(0xAA, vec![car(&mk_claim(nm[i], 0xA1 + i as u8), 30)])).collect());
        sc.block(12, 1600, vec![tx1(0xAA, vec![car(&Action::Transfer { target: b, sel: Some(BitmapSel { anchor: 11, flags: vec![0x05] }) }, 0)])]);
        emit_state(&mut comb, "48_transfer_selective", &sc);
    }

    // 49: |P| = 1000 EXACTLY (inclusive boundary) and EVEN, with an under-claim inside the
    //     window. Lower median = index (1000−1)/2 = 499 of the sorted 100..1099 → 599 → 119,800.
    {
        let w: Vec<u64> = (0..1500u64)
            .map(|i| {
                let cb = if i < 499 {
                    SUBSIDY_FLAT // zero-fee → non-participant
                } else if i == 499 {
                    SUBSIDY_FLAT - 50 // under-claim → non-participant
                } else {
                    SUBSIDY_FLAT + (100 + (i - 500)) * 1000 // fpb 100..1099
                };
                fee_per_byte(cb, SUBSIDY_FLAT, 1000)
            })
            .collect();
        emit_u64(&mut comb, "49_oracle_even_boundary", oracle_rate(&w)); // → 119800
    }

    // 50: odd |P| = 1101 through the participant filter — index 550 of 100..1200 → 650 → 130,000.
    {
        let w: Vec<u64> = (0..2000u64)
            .map(|i| {
                let cb = if i < 899 { SUBSIDY_FLAT } else { SUBSIDY_FLAT + (100 + (i - 899)) * 1000 };
                fee_per_byte(cb, SUBSIDY_FLAT, 1000)
            })
            .collect();
        emit_u64(&mut comb, "50_oracle_odd_median", oracle_rate(&w)); // → 130000
    }

    // 51: |P| = 999 — one short of MIN_FEE_SAMPLE → degrade to DUST_FLOOR exactly.
    {
        let w: Vec<u64> = (0..1500u64)
            .map(|i| {
                let cb = if i < 501 { SUBSIDY_FLAT } else { SUBSIDY_FLAT + (100 + (i - 501)) * 1000 };
                fee_per_byte(cb, SUBSIDY_FLAT, 1000)
            })
            .collect();
        emit_u64(&mut comb, "51_oracle_subsample_floor", oracle_rate(&w)); // → 1
    }

    // 52: charset = a DNS label [a-z0-9-], 1..32: hyphen and a 32-byte name MINT;
    // '.' and '_' DROP (uppercase still drops), leaving exactly the two valid names.
    {
        let mut sc = Sc::new();
        commit_then_claim(&mut sc, 0xAA, b"shib-p2p", 0x71, 10, 1000, 10, 1500, 11);
        commit_then_claim(&mut sc, 0xAA, b"abcdefghijklmnopqrstuvwxyz0123ab", 0x72, 10, 2000, 12, 2500, 13);
        commit_then_claim(&mut sc, 0xAA, b"shib.p2p", 0x73, 10, 3000, 14, 3500, 15);
        commit_then_claim(&mut sc, 0xAA, b"shib_p2p", 0x74, 10, 4000, 16, 4500, 17);
        emit_state(&mut comb, "52_charset", &sc);
    }

    // 52b: structural name rejects — leading/trailing hyphen and xn-- ACE drop.
    {
        let mut sc = Sc::new();
        commit_then_claim(&mut sc, 0xAA, b"-lead", 0x81, 10, 1000, 10, 1500, 11);
        commit_then_claim(&mut sc, 0xAA, b"trail-", 0x82, 10, 2000, 12, 2500, 13);
        commit_then_claim(&mut sc, 0xAA, b"xn--x", 0x83, 10, 3000, 14, 3500, 15);
        commit_then_claim(&mut sc, 0xAA, b"ok-name", 0x84, 10, 4000, 16, 4500, 17);
        emit_state(&mut comb, "52b_structural", &sc);
    }

    // 54: NO per-tx count cap (§0). One tx carries 17 COMMIT carriers past the
    // historical 16; all fold. An impl that caps at 16 either drops the tx or the
    // 17th carrier → a different commit count.
    {
        let mut sc = Sc::new();
        let mut outs: Vec<Output> = (0..17)
            .map(|i| {
                let mut commitment = [0u8; 32];
                commitment[0] = i as u8;
                car(&Action::Commit { commitment }, 0)
            })
            .collect();
        outs.extend((0..17).map(|_| spend(&a, 1)));
        sc.block(10, 1000, vec![tx1(0xAA, outs)]);
        emit_state(&mut comb, "54_no_txcap", &sc);
    }

    // 55: a name minted then RELEASEd earlier in the SAME block re-mints fresh on a
    // later CLAIM in that block (§3.6 "immediately reclaimable"; row existence is
    // authoritative, the block-local claim scratch never blocks a re-mint).
    {
        let mut sc = Sc::new();
        sc.block(10, 1000, vec![tx1(0xAA, vec![car(&mk_commit(b"foo", &a, 0x91), 0)])]);
        sc.block(11, 1500, vec![
            tx1(0xAA, vec![car(&mk_claim(b"foo", 0x91), 10)]),                        // mint foo→A
            tx1(0xAA, vec![car(&Action::Release { anchor: 11, flags: vec![0x01] }, 0)]), // release foo
            tx1(0xAA, vec![car(&mk_claim(b"foo", 0x91), 10)]),                        // re-mint foo→A
        ]);
        emit_state(&mut comb, "55_claim_release_reclaim_sameblock", &sc);
    }

    // 55b: same, but the re-claim is by a DIFFERENT party B whose backing commit has
    // LOWER priority than the departed A's — B still mints fresh.
    {
        let mut sc = Sc::new();
        sc.block(10, 1000, vec![
            tx1(0xAA, vec![car(&mk_commit(b"foo", &a, 0x91), 0)]), // A commit (10, tx0) — higher priority
            tx1(0xBB, vec![car(&mk_commit(b"foo", &b, 0x92), 0)]), // B commit (10, tx1) — lower priority
        ]);
        sc.block(11, 1500, vec![
            tx1(0xAA, vec![car(&mk_claim(b"foo", 0x91), 10)]),                        // A mints
            tx1(0xAA, vec![car(&Action::Release { anchor: 11, flags: vec![0x01] }, 0)]), // A releases
            tx1(0xBB, vec![car(&mk_claim(b"foo", 0x92), 10)]),                        // B mints fresh
        ]);
        emit_state(&mut comb, "55b_reclaim_by_other", &sc);
    }

    // 56: a self-transfer (TRANSFER-all whose target == the current owner) is a real
    // move — it bumps last_set_mutation_height (owner's mut goes 11 → 12), NOT a no-op.
    {
        let mut sc = minted(0xAA, b"bar", 10, 1500);
        sc.block(12, 1600, vec![tx1(0xAA, vec![car(&Action::Transfer { target: a, sel: None }, 0)])]);
        emit_state(&mut comb, "56_self_transfer_bumps_mut", &sc);
    }

    // 57: fee oracle with block_bytes == 0 — the /0 guard substitutes divisor 1 (NOT
    // fee-per-byte 0), so the block still participates. 1000 blocks, each fee 5000 ⇒
    // per-byte 5000 ⇒ median 5000 × REF_SIZE 200 = 1_000_000.
    {
        let sub: u64 = 1_000_000_000_000;
        let cb: u64 = 1_000_000_005_000;
        let by: u64 = 0;
        // Drive the REAL fee_per_byte (now divisor-1 guarded) so the vector exercises the
        // production oracle path, not a copy of the rule.
        let w: Vec<u64> = (0..1000).map(|_| fee_per_byte(cb, sub, by)).collect();
        emit_u64(&mut comb, "57_oracle_zero_bytes", oracle_rate(&w));
    }

    // 58: CLAIM burn near 2⁶⁴ at rate = DUST_FLOOR (1) — the lease day-count T overflows
    // 64 bits and clamps to MAX_LEASE (365 days).
    {
        let mut sc = Sc::new();
        let blk10 = Block { height: 10, timestamp: 1000, rate: 1, txs: vec![tx1(0xAA, vec![car(&mk_commit(b"foo", &a, 0x95), 0)])] };
        sc.st.apply_block(&blk10, &vec![1000i64; 10]);
        let blk11 = Block { height: 11, timestamp: 1500, rate: 1, txs: vec![tx1(0xAA, vec![car(&mk_claim(b"foo", 0x95), u64::MAX)])] };
        sc.st.apply_block(&blk11, &vec![1500i64; 11]);
        emit_state(&mut comb, "58_lease_clamp_huge_burn", &sc);
    }

    let cd = sha256(&comb);
    println!("combined {}", hex32(&cd));
    0
}
