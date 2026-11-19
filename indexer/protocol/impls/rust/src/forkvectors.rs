//! Consensus-fork differential vectors (TV-1/5b/6/7/8 + M9 + H8 + H3), mirroring
//! `impls/c forkvectors` / `impls/ts forkvectors`. Each builds a construction against
//! THIS impl and asserts the SPEC-pinned (2026-06-29) outcome. Independent reference-tier
//! impls cannot share the gen.c seed-soak (their generators differ by construction), so they
//! instead each reproduce the spec outcome for every consensus-critical vector — three
//! independent impls agreeing on every fork vector is the strongest correctness signal.
//!
//! MTP control: this impl derives MTP from the timestamp array (median of the 11 prior
//! blocks, §5), not directly. We use a monotone array `ts[i] = base + i*step` and apply blocks
//! at heights ≥ 11, where the window is a full 11 and `MTP(H) = ts[H-6] = base + (H-6)*step`.
//! That gives exact per-block MTP control for the boundary vectors (TV-1 at +COMMIT_EXPIRY,
//! TV-7 at +1 day). Only the meaningful blocks are applied; the earlier indices just populate
//! the array the median reads.

use crate::decode::{Action, BitmapSel, RenewMode};
use crate::encode::encode_action;
use crate::fold::{St, State};
use crate::model::{Block, Input, Output, Tx};
use crate::sha256::sha256;
use crate::types::{Hash160, ScriptType, BILLING_UNIT, COMMIT_EXPIRY};

fn fid(b: u8) -> Hash160 {
    [b; 20]
}

fn commitment_of(salt: &[u8; 32], name: &[u8], author: &Hash160) -> [u8; 32] {
    let mut pre = Vec::with_capacity(32 + name.len() + 20);
    pre.extend_from_slice(salt);
    pre.extend_from_slice(name);
    pre.extend_from_slice(author);
    sha256(&pre)
}

fn inp(id: Hash160) -> Input {
    Input { identity: Some(id), stype: ScriptType::P2pkh, sighash_all: true }
}

/// An input that exists but did NOT sign SIGHASH_ALL → resolve_actor yields ⊥ (M9).
fn inp_bottom() -> Input {
    Input { identity: Some(fid(0x99)), stype: ScriptType::P2pkh, sighash_all: false }
}

fn carrier(act: &Action, value: u64) -> Output {
    Output::Carrier { payload: encode_action(act), value }
}

/// Harness over the block-oriented fold with a prebuilt monotone timestamp array.
struct Fv {
    st: State,
    ts: Vec<i64>,
    rate: u64,
}

impl Fv {
    fn new(step: i64, max_h: i64) -> Self {
        let base: i64 = 1_000_000;
        let ts: Vec<i64> = (0..=max_h).map(|i| base + i * step).collect();
        Fv { st: State::new(0), ts, rate: 28 } // rate 28 ⇒ burn N koinu buys exactly N days
    }
    fn apply(&mut self, height: i64, txs: Vec<Tx>) {
        let blk = Block { height, timestamp: self.ts[height as usize], rate: self.rate, txs };
        self.st.apply_block(&blk, &self.ts);
    }
    fn owns(&self, id: Hash160, name: &[u8]) -> bool {
        self.st.names.get(name).map(|r| r.st == St::Owned && r.owner == id).unwrap_or(false)
    }
    fn lease(&self, name: &[u8]) -> i64 {
        self.st.names.get(name).map(|r| r.lease_expiry).unwrap_or(-1)
    }
    fn st_of(&self, name: &[u8]) -> Option<St> {
        self.st.names.get(name).map(|r| r.st)
    }
    fn has_mut(&self, id: Hash160) -> bool {
        self.st.muts.contains_key(&id)
    }
}

struct Report {
    pass: u32,
    fail: u32,
}
impl Report {
    fn check(&mut self, tv: &str, desc: &str, got: &str, want: &str) {
        let ok = got == want;
        if ok {
            self.pass += 1;
        } else {
            self.fail += 1;
        }
        println!(
            "  {:<6} {:<46} rust={:<7} spec={:<7} {}",
            tv,
            desc,
            got,
            want,
            if ok { "MATCH" } else { "*** DIVERGE ***" }
        );
    }
}

pub fn run() -> i32 {
    let mut rep = Report { pass: 0, fail: 0 };
    let a = fid(0xaa);
    let b = fid(0xbb);

    // TV-1: COMMIT_EXPIRY inclusive — a claim at MTP == commit_time + COMMIT_EXPIRY still mints.
    {
        // step = COMMIT_EXPIRY ⇒ MTP(21) - MTP(20) = COMMIT_EXPIRY exactly.
        let mut fv = Fv::new(COMMIT_EXPIRY, 21);
        let cm = commitment_of(&[0x11; 32], b"edge", &a);
        fv.apply(20, vec![Tx { inputs: vec![inp(a)], outputs: vec![carrier(&Action::Commit { commitment: cm }, 0)] }]);
        fv.apply(
            21,
            vec![Tx { inputs: vec![inp(a)], outputs: vec![carrier(&Action::Claim { salt: [0x11; 32], name: b"edge".to_vec() }, 10)] }],
        );
        rep.check("TV-1", "COMMIT_EXPIRY inclusive boundary", if fv.owns(a, b"edge") { "mint" } else { "drop" }, "mint");
    }

    // TV-5b: one author, two matching commits (tx0,tx2) + a rival (tx1) — author (min commit
    // tx_index) wins regardless of claim chain order (the §3.2 tuple is the COMMIT's tx_index).
    {
        let mut fv = Fv::new(1000, 21);
        let ca = commitment_of(&[0x11; 32], b"dup", &a);
        let cb = commitment_of(&[0x22; 32], b"dup", &b);
        fv.apply(20, vec![
            Tx { inputs: vec![inp(a)], outputs: vec![carrier(&Action::Commit { commitment: ca }, 0)] }, // tx0
            Tx { inputs: vec![inp(b)], outputs: vec![carrier(&Action::Commit { commitment: cb }, 0)] }, // tx1
            Tx { inputs: vec![inp(a)], outputs: vec![carrier(&Action::Commit { commitment: ca }, 0)] }, // tx2
        ]);
        fv.apply(21, vec![
            Tx { inputs: vec![inp(b)], outputs: vec![carrier(&Action::Claim { salt: [0x22; 32], name: b"dup".to_vec() }, 10)] }, // rival claims first
            Tx { inputs: vec![inp(a)], outputs: vec![carrier(&Action::Claim { salt: [0x11; 32], name: b"dup".to_vec() }, 10)] }, // author claims second
        ]);
        let got = if fv.owns(a, b"dup") { "A wins" } else if fv.owns(b, b"dup") { "B wins" } else { "none" };
        rep.check("TV-5b", "claim multiplicity (author min-tuple)", got, "A wins");
    }

    // TV-6: bitmap LSB-first — flag 0x01 selects lexicographic name 0 (aa).
    {
        let mut fv = Fv::new(1000, 22);
        let names: [&[u8]; 3] = [b"aa", b"bb", b"cc"];
        let salts = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let commits: Vec<Output> = (0..3).map(|i| carrier(&Action::Commit { commitment: commitment_of(&salts[i], names[i], &a) }, 0)).collect();
        fv.apply(20, vec![Tx { inputs: vec![inp(a)], outputs: commits }]);
        let claims: Vec<Output> = (0..3).map(|i| carrier(&Action::Claim { salt: salts[i], name: names[i].to_vec() }, 1)).collect();
        fv.apply(21, vec![Tx { inputs: vec![inp(a)], outputs: claims }]);
        let aa0 = fv.lease(b"aa");
        let bb0 = fv.lease(b"bb");
        fv.apply(22, vec![Tx { inputs: vec![inp(a)], outputs: vec![carrier(&Action::Renew { mode: RenewMode::Selective { anchor: 21, flags: vec![0x01] } }, 10)] }]);
        let got = if fv.lease(b"aa") > aa0 && fv.lease(b"bb") == bb0 { "aa" } else { "other" };
        rep.check("TV-6", "bitmap LSB-first (0x01 -> aa)", got, "aa");
    }

    // TV-7: a pre-block LAPSE bumps last_set_mutation_height (§3.5), so a selective RENEW
    // anchored at H-1 (before the lapse) is REJECTED — not applied against a now-stale ordering.
    {
        // step = 1 day ⇒ MTP(22) - MTP(21) = BILLING_UNIT, and "aa" (burn 1) leases exactly 1 day.
        let mut fv = Fv::new(BILLING_UNIT as i64, 22);
        let caa = commitment_of(&[0x11; 32], b"aa", &a);
        let ckeep = commitment_of(&[0x22; 32], b"keep", &a);
        fv.apply(20, vec![Tx { inputs: vec![inp(a)], outputs: vec![
            carrier(&Action::Commit { commitment: caa }, 0),
            carrier(&Action::Commit { commitment: ckeep }, 0),
        ] }]);
        fv.apply(21, vec![Tx { inputs: vec![inp(a)], outputs: vec![
            carrier(&Action::Claim { salt: [0x11; 32], name: b"aa".to_vec() }, 1),     // 1 day
            carrier(&Action::Claim { salt: [0x22; 32], name: b"keep".to_vec() }, 100), // 100 days
        ] }]);
        let keep0 = fv.lease(b"keep");
        // block 22: "aa" lapses pre-block at its expiry, bumping A's mut height to 22; the RENEW
        // anchored at 21 then fails the anchor guard (last_mut 22 > anchor 21).
        fv.apply(22, vec![Tx { inputs: vec![inp(a)], outputs: vec![carrier(&Action::Renew { mode: RenewMode::Selective { anchor: 21, flags: vec![0x01] } }, 10)] }]);
        rep.check("TV-7", "lapse bumps mut height (stale RENEW)", if fv.lease(b"keep") > keep0 { "ACCEPT" } else { "REJECT" }, "REJECT");
    }

    // TV-8: a selective TRANSFER selecting a LOCKED (listed) name skips it, moves the rest.
    {
        let mut fv = Fv::new(1000, 23);
        let t = fid(0x77);
        let names: [&[u8]; 3] = [b"aa", b"bb", b"cc"];
        let salts = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let commits: Vec<Output> = (0..3).map(|i| carrier(&Action::Commit { commitment: commitment_of(&salts[i], names[i], &a) }, 0)).collect();
        fv.apply(20, vec![Tx { inputs: vec![inp(a)], outputs: commits }]);
        let claims: Vec<Output> = (0..3).map(|i| carrier(&Action::Claim { salt: salts[i], name: names[i].to_vec() }, 200)).collect();
        fv.apply(21, vec![Tx { inputs: vec![inp(a)], outputs: claims }]);
        fv.apply(22, vec![Tx { inputs: vec![inp(a)], outputs: vec![carrier(&Action::Sell { price: 300, window: 20000, name: b"bb".to_vec() }, 0)] }]); // bb LISTED (locked)
        fv.apply(23, vec![Tx { inputs: vec![inp(a)], outputs: vec![carrier(&Action::Transfer { target: t, sel: Some(BitmapSel { anchor: 22, flags: vec![0x03] }) }, 0)] }]); // bits 0,1 → aa,bb
        let ok = fv.owns(t, b"aa") && fv.st_of(b"bb") == Some(St::Listed) && fv.owns(a, b"cc");
        rep.check("TV-8", "locked-name selective skip", if ok { "skip" } else { "other" }, "skip");
    }

    // M9: TRADE is attributed to its named parties (idxA/idxB), NOT the acting identity. A TRADE
    // whose vin[0] is ⊥ (didn't sign SIGHASH_ALL) still settles if both named parties are valid.
    {
        let mut fv = Fv::new(1000, 22);
        let cna = commitment_of(&[0x11; 32], b"na", &a);
        let cnb = commitment_of(&[0x22; 32], b"nb", &b);
        fv.apply(20, vec![
            Tx { inputs: vec![inp(a)], outputs: vec![carrier(&Action::Commit { commitment: cna }, 0)] },
            Tx { inputs: vec![inp(b)], outputs: vec![carrier(&Action::Commit { commitment: cnb }, 0)] },
        ]);
        fv.apply(21, vec![
            Tx { inputs: vec![inp(a)], outputs: vec![carrier(&Action::Claim { salt: [0x11; 32], name: b"na".to_vec() }, 50)] },
            Tx { inputs: vec![inp(b)], outputs: vec![carrier(&Action::Claim { salt: [0x22; 32], name: b"nb".to_vec() }, 50)] },
        ]);
        // vin[0] = ⊥; named parties are vin[1]=A, vin[2]=B.
        fv.apply(22, vec![Tx {
            inputs: vec![inp_bottom(), inp(a), inp(b)],
            outputs: vec![carrier(&Action::Trade { idx_a: 1, idx_b: 2, name_a: b"na".to_vec(), name_b: b"nb".to_vec() }, 0)],
        }]);
        let got = if fv.owns(b, b"na") && fv.owns(a, b"nb") { "swap" } else { "drop" };
        rep.check("M9", "TRADE bypasses bottom acting identity", got, "swap");
    }

    // H8: a used COMMIT lingers (NOT consumed on use) until its time-prune (§3.2; digest-affecting).
    {
        // step in (COMMIT_EXPIRY/2, COMMIT_EXPIRY]: commit live at the claim, pruned one block later.
        let mut fv = Fv::new(10000, 22);
        let cm = commitment_of(&[0x11; 32], b"edge", &a);
        fv.apply(20, vec![Tx { inputs: vec![inp(a)], outputs: vec![carrier(&Action::Commit { commitment: cm }, 0)] }]);
        fv.apply(21, vec![Tx { inputs: vec![inp(a)], outputs: vec![carrier(&Action::Claim { salt: [0x11; 32], name: b"edge".to_vec() }, 10)] }]);
        let lingers = fv.st.commits.len() == 1; // claim did NOT remove the backing commit
        fv.apply(22, vec![]); // empty block: pre-block prune crosses the window
        let pruned = fv.st.commits.is_empty();
        rep.check("H8", "used commit lingers then time-prunes", if lingers && pruned { "linger" } else { "other" }, "linger");
    }

    // H3: a per-owner mutation height persists after the owner's set empties (§3.5/§3.9; digest-affecting).
    {
        let mut fv = Fv::new(1000, 22);
        let cm = commitment_of(&[0x11; 32], b"solo", &a);
        fv.apply(20, vec![Tx { inputs: vec![inp(a)], outputs: vec![carrier(&Action::Commit { commitment: cm }, 0)] }]);
        fv.apply(21, vec![Tx { inputs: vec![inp(a)], outputs: vec![carrier(&Action::Claim { salt: [0x11; 32], name: b"solo".to_vec() }, 10)] }]);
        fv.apply(22, vec![Tx { inputs: vec![inp(a)], outputs: vec![carrier(&Action::Release { anchor: 21, flags: vec![0x01] }, 0)] }]); // releases solo → set empties
        let empty = fv.st_of(b"solo").is_none();
        let mut_kept = fv.has_mut(a);
        rep.check("H3", "mut row persists after set empties", if empty && mut_kept { "kept" } else { "other" }, "kept");
    }

    println!("────");
    println!("forkvectors: {} match, {} diverge (fold layer; spec-pinned 2026-06-29 reading)", rep.pass, rep.fail);
    if rep.fail > 0 {
        1
    } else {
        0
    }
}
