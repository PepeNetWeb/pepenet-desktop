//! Hand-authored vector battery. Asserts outcomes derived from the prose (§3/§4/§5).
//! Every boundary the SPEC-RATIONALE.md flags has a probe here.

use crate::attrib::*;
use crate::decode::*;
use crate::digest::*;
use crate::encode::*;
use crate::fold::*;
use crate::model::*;
use crate::prng::SplitMix64;
use crate::ripemd160::{hash160, ripemd160};
use crate::sha256::sha256;
use crate::types::*;

struct T {
    pass: u32,
    fail: u32,
}
impl T {
    fn check(&mut self, name: &str, cond: bool) {
        if cond {
            self.pass += 1;
        } else {
            self.fail += 1;
            println!("  FAIL: {}", name);
        }
    }
}

fn ident(i: u8) -> Hash160 {
    let mut h = [0u8; 20];
    h[0] = i;
    h[19] = i;
    h
}
fn pk_in(a: Hash160) -> Input {
    Input { identity: Some(a), stype: ScriptType::P2pkh, sighash_all: true }
}
fn carrier(a: &Action, value: u64) -> Output {
    Output::Carrier { payload: encode_action(a), value }
}
fn spend(h: Hash160, v: u64) -> Output {
    Output::Spend { hash160: h, stype: ScriptType::P2pkh, value: v }
}

struct Chain {
    st: State,
    ts: Vec<i64>,
}
impl Chain {
    fn new() -> Self {
        Chain { st: State::new(0), ts: Vec::new() }
    }
    fn block(&mut self, height: i64, timestamp: i64, rate: u64, txs: Vec<Tx>) {
        assert_eq!(height as usize, self.ts.len(), "heights must be sequential");
        self.ts.push(timestamp);
        let blk = Block { height, timestamp, rate, txs };
        self.st.apply_block(&blk, &self.ts);
    }
}

fn commitment_of(salt: &[u8; 32], name: &[u8], author: &Hash160) -> [u8; 32] {
    let mut pre = Vec::new();
    pre.extend_from_slice(salt);
    pre.extend_from_slice(name);
    pre.extend_from_slice(author);
    sha256(&pre)
}

pub fn run() -> bool {
    let mut t = T { pass: 0, fail: 0 };
    crypto_kats(&mut t);
    roundtrips(&mut t);
    decode_cases(&mut t);
    fold_vectors(&mut t);
    dotted_names(&mut t);
    oracle_kats(&mut t);
    replay_kats(&mut t);
    attrib_kats(&mut t);
    secp_kats(&mut t);
    ecmh_state_kats(&mut t);
    let e = State::new(0);
    println!("empty_state_digest={}", hex32(&state_digest(&e)));
    println!("empty_state_ecmh={}", hex32(&state_ecmh(&e)));
    println!("selftest: {} passed, {} failed", t.pass, t.fail);
    t.fail == 0
}

fn ecmh_state_kats(t: &mut T) {
    // §13.2 ECMH primitive algebra (identity / commutativity / inverse / round-trip).
    t.check("ECMH algebra (identity/commutativity/inverse)", crate::secp256k1::secp_selftest_ecmh() == 0);

    // Empty-state ECMH is stable across independent recomputes and matches the
    // cross-impl anchor.
    let ea = state_ecmh(&State::new(0));
    let eb = state_ecmh(&State::new(0));
    t.check("ECMH empty-state stable", ea == eb);
    t.check(
        "ECMH empty-state cross-impl anchor",
        hex32(&ea) == "3ecfc3d7fa5be56fc513dde926bdf105c92accbf07088e702f85856fa69d10e0",
    );

    // ECMH induces the SAME equality relation as state_digest. Build the same
    // logical rows in two insertion orders (commit a,b in order in both; CLAIM
    // reversed in s2 ⇒ the names map content is identical, the commits identical),
    // plus a smaller third state that genuinely differs.
    let a = ident(0xAA);
    let sa = [0xA1u8; 32];
    let sb = [0xA2u8; 32];
    let cma = commitment_of(&sa, b"a", &a);
    let cmb = commitment_of(&sb, b"b", &a);

    let mut s1 = Chain::new();
    s1.block(0, 1000, 28, vec![
        Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Commit { commitment: cma }, 0)] },
        Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Commit { commitment: cmb }, 0)] },
    ]);
    s1.block(1, 1500, 28, vec![
        Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Claim { salt: sa, name: b"a".to_vec() }, 30)] },
        Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Claim { salt: sb, name: b"b".to_vec() }, 30)] },
    ]);

    let mut s2 = Chain::new();
    s2.block(0, 1000, 28, vec![
        Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Commit { commitment: cma }, 0)] },
        Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Commit { commitment: cmb }, 0)] },
    ]);
    s2.block(1, 1500, 28, vec![
        Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Claim { salt: sb, name: b"b".to_vec() }, 30)] },
        Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Claim { salt: sa, name: b"a".to_vec() }, 30)] },
    ]);

    let mut s3 = Chain::new();
    s3.block(0, 1000, 28, vec![Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Commit { commitment: cma }, 0)] }]);
    s3.block(1, 1500, 28, vec![Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Claim { salt: sa, name: b"a".to_vec() }, 30)] }]);

    let d1 = state_digest(&s1.st);
    let d2 = state_digest(&s2.st);
    let d3 = state_digest(&s3.st);
    let e1 = state_ecmh(&s1.st);
    let e2 = state_ecmh(&s2.st);
    let e3 = state_ecmh(&s3.st);
    t.check("ECMH test setup: reordered builds give equal digest", d1 == d2);
    t.check("ECMH equality tracks digest (equal states)", (d1 == d2) == (e1 == e2));
    t.check("ECMH equality tracks digest (differing states)", (d1 == d3) == (e1 == e3));
}

fn oracle_kats(t: &mut T) {
    use crate::oracle::{fee_per_byte, mtp, oracle_rate};
    // signed under-claim clamp: coinbase < subsidy → 0 fees (no unsigned wrap)
    t.check("oracle under-claim → 0", fee_per_byte(SUBSIDY_FLAT - 5, SUBSIDY_FLAT, 100) == 0);
    // floor division per block
    t.check("oracle floor div", fee_per_byte(SUBSIDY_FLAT + 1000, SUBSIDY_FLAT, 9) == 111);
    // block_bytes == 0 → divisor pinned to 1 (block still participates), NOT fee-per-byte 0
    t.check("oracle zero bytes → divisor 1", fee_per_byte(SUBSIDY_FLAT + 5000, SUBSIDY_FLAT, 0) == 5000);
    // participant median × REF_SIZE: zeros are filtered (non-participants), median over P only
    let mut w = vec![2u64; 1_001];
    w.extend(std::iter::repeat(0u64).take(500)); // zero-fee blocks do not participate
    t.check("oracle median×REF_SIZE", oracle_rate(&w) == 2 * REF_SIZE);
    // clamp ceiling (|P| = MIN_FEE_SAMPLE exactly — also covers the inclusive boundary)
    let big = vec![RATE_CAP; MIN_FEE_SAMPLE];
    t.check("oracle clamp ceiling", oracle_rate(&big) == RATE_CAP);
    // degrade floor (|P| = 0 < MIN_FEE_SAMPLE → DUST_FLOOR)
    t.check("oracle clamp floor", oracle_rate(&[0, 0, 0]) == DUST_FLOOR);
    // §3.4 participant-median vectors (mirroring impls/c scenario 49–51), built from
    // (coinbase, subsidy, bytes) through fee_per_byte so the signed clamp is exercised.
    // 49: |P| = 1000 EXACTLY (inclusive boundary) and EVEN, with an under-claim block
    //     inside the window. Lower median = sorted index (1000−1)/2 = 499 of 100..1099
    //     → 599 → 599 × REF_SIZE = 119_800. An unsigned wrap enrolls the under-claim as
    //     a huge 1001st participant → 120_000; an exclusive boundary → 1; an upper
    //     median → 120_000 — every rival reading forks to a different number.
    let w49: Vec<u64> = (0..1500u64)
        .map(|i| {
            let cb = if i < 499 {
                SUBSIDY_FLAT // zero-fee → non-participant
            } else if i == 499 {
                SUBSIDY_FLAT - 50 // under-claim → clamps to 0 → non-participant
            } else {
                SUBSIDY_FLAT + (100 + (i - 500)) * 1000 // fpb 100..1099
            };
            fee_per_byte(cb, SUBSIDY_FLAT, 1000)
        })
        .collect();
    t.check("oracle even |P|=1000 boundary lower-median", oracle_rate(&w49) == 119_800);
    // 50: odd |P| = 1101 through the participant filter — index 550 of 100..1200 → 650 → 130_000.
    let w50: Vec<u64> = (0..2000u64)
        .map(|i| {
            let cb = if i < 899 { SUBSIDY_FLAT } else { SUBSIDY_FLAT + (100 + (i - 899)) * 1000 };
            fee_per_byte(cb, SUBSIDY_FLAT, 1000)
        })
        .collect();
    t.check("oracle odd |P|=1101 median", oracle_rate(&w50) == 130_000);
    // 51: |P| = 999 — one short of MIN_FEE_SAMPLE → degrade to DUST_FLOOR exactly.
    let w51: Vec<u64> = (0..1500u64)
        .map(|i| {
            let cb = if i < 501 { SUBSIDY_FLAT } else { SUBSIDY_FLAT + (100 + (i - 501)) * 1000 };
            fee_per_byte(cb, SUBSIDY_FLAT, 1000)
        })
        .collect();
    t.check("oracle |P|=999 degrade", oracle_rate(&w51) == DUST_FLOOR);
    // FEE_WINDOW is odd (single-element median guarantee)
    t.check("FEE_WINDOW odd", FEE_WINDOW % 2 == 1);
    // MTP: genesis 0; short window upper-middle; full window
    t.check("mtp genesis 0", mtp(0, &[]) == 0);
    t.check("mtp k=1", mtp(1, &[100]) == 100);
    // even short window k=2 → upper-middle (index k/2 = 1)
    t.check("mtp even upper-middle", mtp(2, &[50, 90]) == 90);
    // 12 predecessors → median of [H-11..H-1] = 11 values
    let ts: Vec<i64> = (0..13).map(|i| (i * 10) as i64).collect();
    // H=12 → window indices 1..=11 = [10,20,...,110]; median (index 5) = 60
    t.check("mtp full window median", mtp(12, &ts) == 60);
    let _ = RESERVE_DEPOSIT_BPS; // referenced constant
}

fn replay_kats(t: &mut T) {
    // The fold is a pure function of the block sequence (§5 reorg model): two independent
    // folds of the same chain produce the same digest; clear() leaves no residue.
    let a = ident(1);
    let s = [3u8; 32];
    let d1 = state_digest(&mint_chain(a, b"rep", &s).st);
    let d2 = state_digest(&mint_chain(a, b"rep", &s).st);
    t.check("replay determinism", d1 == d2);
    let mut c = mint_chain(a, b"rep", &s);
    t.check("state has 1 owned name", state_n_owned(&c.st) == 1);
    c.st.clear();
    t.check("clear() empties state", state_n_owned(&c.st) == 0 && state_digest(&c.st) == state_digest(&State::new(0)));
}

fn secp_kats(t: &mut T) {
    use crate::secp256k1::{secp_ecdsa_sign, secp_ecdsa_verify, secp_on_curve, secp_pubkey, secp_selftest};
    // bundled curve KAT (constants, 2G, n·G=∞, decompress G, sign/verify+tamper round-trips).
    t.check("secp_selftest (constants/2G/nG=inf/decompress/sign-verify)", secp_selftest() == 0);
    // priv=1 ⇒ G (compressed, even Gy).
    let mut p1 = [0u8; 32];
    p1[31] = 1;
    let pk1 = secp_pubkey(&p1).expect("priv1 pubkey");
    t.check(
        "secp priv1 = compressed G",
        hex33(&pk1) == "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    );
    // priv=2 ⇒ 2G (compressed, even).
    let mut p2 = [0u8; 32];
    p2[31] = 2;
    let pk2 = secp_pubkey(&p2).expect("priv2 pubkey");
    t.check(
        "secp priv2 = compressed 2G",
        hex33(&pk2) == "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    );
    // on-curve membership at the edges.
    let mut gcomp = [0u8; 33];
    gcomp.copy_from_slice(&pk1);
    t.check("secp on_curve(G compressed)", secp_on_curve(&gcomp));
    let mut bad = gcomp;
    bad[0] = 0x05;
    t.check("secp on_curve bad prefix → false", !secp_on_curve(&bad));
    // sign/verify a deterministic message + tamper + wrong-key rejection.
    let mut priv_ = [0u8; 32];
    priv_[31] = 0x2A;
    let pubk = secp_pubkey(&priv_).expect("pubkey");
    let h = sha256(b"secp kat message");
    let (r, s) = secp_ecdsa_sign(&priv_, &h).expect("sign");
    t.check("secp sign/verify accept", secp_ecdsa_verify(&h, &r, &s, &pubk));
    let mut hbad = h;
    hbad[0] ^= 0x01;
    t.check("secp tamper → reject", !secp_ecdsa_verify(&hbad, &r, &s, &pubk));
    let mut wrongpub = pubk;
    wrongpub[0] ^= 0x01; // flip parity ⇒ wrong point
    t.check("secp wrong key → reject", !secp_ecdsa_verify(&h, &r, &s, &wrongpub));
}

fn hex33(d: &[u8; 33]) -> String {
    let mut s = String::new();
    for b in d {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn crypto_kats(t: &mut T) {
    t.check(
        "sha256(\"\")",
        hex32(&sha256(b"")) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    t.check(
        "sha256(abc)",
        hex32(&sha256(b"abc")) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    let mut r = SplitMix64::new(0);
    t.check("splitmix64 seed0", r.next() == 0xE220A8397B1DCDAF);
    t.check("ripemd160(\"\")", hex20(&ripemd160(b"")) == "9c1185a5c5e9fc54612808977ee8f548b2258d31");
    t.check(
        "ripemd160(abc)",
        hex20(&ripemd160(b"abc")) == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
    );
    t.check("hash160(abc)", hex20(&hash160(b"abc")) == "bb1be98c142444d7a56aa3981c3942a978e4dc33");
}

fn hex20(d: &[u8; 20]) -> String {
    let mut s = String::new();
    for b in d {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn roundtrips(t: &mut T) {
    let acts = vec![
        Action::Commit { commitment: [4u8; 32] },
        Action::Claim { salt: [1u8; 32], name: b"alice".to_vec() },
        Action::Renew { mode: RenewMode::All },
        Action::Renew { mode: RenewMode::AllSafe { anchor: 1234 } },
        Action::Renew { mode: RenewMode::Selective { anchor: 99, flags: vec![0xAB, 0x01] } },
        Action::Transfer { target: ident(5), sel: None },
        Action::Transfer { target: ident(5), sel: Some(BitmapSel { anchor: 50, flags: vec![0x03] }) },
        Action::Sell { price: 1000, window: 0, name: b"bob".to_vec() },
        Action::Reserve { name: b"bob".to_vec() },
        Action::Settle { name: b"bob".to_vec() },
        Action::Release { anchor: 7, flags: vec![0x01] },
        Action::SellTo { price: 500, buyer: ident(8), name: b"car".to_vec() },
        Action::Pay { name: b"car".to_vec() },
        Action::As { index: 2 },
        Action::Trade { idx_a: 0, idx_b: 1, name_a: b"a".to_vec(), name_b: b"bb".to_vec() },
    ];
    for a in &acts {
        let enc = encode_action(a);
        let dec = decode_payload(&enc, 1);
        t.check(&format!("roundtrip {:?}", a), dec == Decoded::Action(a.clone()));
    }
}

fn decode_cases(t: &mut T) {
    // names-only demux: bare UTF-8 is IGNORE (no posts projection)
    t.check("utf8 noise ignore", matches!(decode_payload(b"hello world", 1), Decoded::Ignore));
    t.check("zero-value noise ignore", matches!(decode_payload(b"hello", 0), Decoded::Ignore));
    // 0xFF lead with unknown opcode
    t.check("0xff lead ignore", matches!(decode_payload(&[0xFF, 0x50, 0x4E, 0xEE], 1), Decoded::Ignore));
    // overlay band opcode
    t.check("overlay band ignore", matches!(decode_payload(&[0xFF, 0x50, 0x4E, 0xD6, 0x00], 1), Decoded::Ignore));
    // uppercase name in CLAIM -> ignore (reject, never fold)
    let mut bad = vec![0xFF, 0x50, 0x4E, OP_CLAIM];
    bad.extend_from_slice(&[0u8; 32]);
    bad.extend_from_slice(b"Alice");
    t.check("uppercase name reject", matches!(decode_payload(&bad, 0), Decoded::Ignore));
    // structural name rejects
    let mut lead = vec![0xFF, 0x50, 0x4E, OP_CLAIM];
    lead.extend_from_slice(&[0u8; 32]);
    lead.extend_from_slice(b"-a");
    t.check("leading hyphen reject", matches!(decode_payload(&lead, 0), Decoded::Ignore));
    let mut ace = vec![0xFF, 0x50, 0x4E, OP_CLAIM];
    ace.extend_from_slice(&[0u8; 32]);
    ace.extend_from_slice(b"xn--x");
    t.check("ACE prefix reject", matches!(decode_payload(&ace, 0), Decoded::Ignore));
    // RENEW length 5..8 (bl 1..4) invalid
    let r7 = vec![0xFF, 0x50, 0x4E, OP_RENEW, 0x00, 0x00, 0x00]; // bl=3
    t.check("renew bl3 invalid", matches!(decode_payload(&r7, 0), Decoded::Ignore));

    // §6 pinned carrier ceiling: flags at the exact consensus caps decode;
    // one byte past the ceiling is IGNORE (fail-closed).
    let mut wide = vec![0xFF, 0x50, 0x4E, OP_RENEW];
    wide.extend_from_slice(&[7, 0, 0, 0, 0]); // anchor5
    wide.extend((0..FLAGS_MAX).map(|i| (i * 7 + 1) as u8));
    t.check("renew at cap is exactly CARRIER_MAX bytes", wide.len() == CARRIER_MAX);
    t.check(
        "renew-selective decodes with all 9987 flag bytes",
        matches!(&decode_payload(&wide, 0),
                 Decoded::Action(Action::Renew { mode: RenewMode::Selective { flags, .. } })
                 if flags.len() == FLAGS_MAX),
    );
    wide.push(0x00);
    t.check("one byte past the L1 ceiling ignore", matches!(decode_payload(&wide, 0), Decoded::Ignore));
    let mut xfer = vec![0xFF, 0x50, 0x4E, OP_TRANSFER];
    xfer.extend_from_slice(&[0xBB; 20]);
    xfer.extend_from_slice(&[7, 0, 0, 0, 0]);
    xfer.extend(std::iter::repeat(0x01).take(FLAGS_XFER_MAX));
    t.check(
        "transfer-selective decodes at FLAGS_XFER_MAX",
        matches!(&decode_payload(&xfer, 0),
                 Decoded::Action(Action::Transfer { sel: Some(BitmapSel { flags, .. }), .. })
                 if flags.len() == FLAGS_XFER_MAX),
    );
    xfer.push(0x00);
    t.check("transfer flags past the cap ignore", matches!(decode_payload(&xfer, 0), Decoded::Ignore));
    let mut rel = vec![0xFF, 0x50, 0x4E, OP_RELEASE];
    rel.extend_from_slice(&[3, 0, 0, 0, 0]);
    rel.extend(std::iter::repeat(0xFF).take(FLAGS_MAX));
    t.check(
        "release decodes at FLAGS_MAX",
        matches!(&decode_payload(&rel, 0),
                 Decoded::Action(Action::Release { flags, .. }) if flags.len() == FLAGS_MAX),
    );
    // TRADE two commas -> ignore
    let mut tr = vec![0xFF, 0x50, 0x4E, OP_TRADE, 0, 1];
    tr.extend_from_slice(b"a,b,c");
    t.check("trade two commas", matches!(decode_payload(&tr, 0), Decoded::Ignore));
}

fn fold_vectors(t: &mut T) {
    let a = ident(1);
    let b = ident(2);
    let s = [3u8; 32];

    // T1: commit -> claim happy
    {
        let mut c = Chain::new();
        let cm = commitment_of(&s, b"alice", &a);
        c.block(0, 100, 28, vec![Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Commit { commitment: cm }, 0)] }]);
        c.block(1, 200, 28, vec![Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Claim { salt: s, name: b"alice".to_vec() }, 1)] }]);
        t.check("T1 claim mints", c.st.names.get(b"alice".as_slice()).map(|r| r.owner == a).unwrap_or(false));
    }

    // T2: naked claim (no commit) -> drop
    {
        let mut c = Chain::new();
        c.block(0, 100, 28, vec![Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Claim { salt: s, name: b"x".to_vec() }, 1)] }]);
        t.check("T2 naked claim drops", !c.st.names.contains_key(b"x".as_slice()));
    }

    // T3: same-block commit too shallow -> claim drops
    {
        let mut c = Chain::new();
        let cm = commitment_of(&s, b"y", &a);
        c.block(0, 100, 28, vec![
            Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Commit { commitment: cm }, 0)] },
            Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Claim { salt: s, name: b"y".to_vec() }, 1)] },
        ]);
        t.check("T3 same-block too shallow", !c.st.names.contains_key(b"y".as_slice()));
    }

    // T4: priority tuple — lower commit tx_index wins regardless of claim order
    {
        let mut c = Chain::new();
        let sa = [10u8; 32];
        let sb = [11u8; 32];
        let cma = commitment_of(&sa, b"z", &a); // tx_index 0
        let cmb = commitment_of(&sb, b"z", &b); // tx_index 1
        c.block(0, 100, 28, vec![
            Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Commit { commitment: cma }, 0)] },
            Tx { inputs: vec![pk_in(b)], outputs: vec![carrier(&Action::Commit { commitment: cmb }, 0)] },
        ]);
        // claim by B first (tx0), then A (tx1) — A's commit tx_index (0) is lower → A wins
        c.block(1, 200, 28, vec![
            Tx { inputs: vec![pk_in(b)], outputs: vec![carrier(&Action::Claim { salt: sb, name: b"z".to_vec() }, 1)] },
            Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Claim { salt: sa, name: b"z".to_vec() }, 1)] },
        ]);
        t.check("T4 priority commit-tx_index wins", c.st.names.get(b"z".as_slice()).map(|r| r.owner == a).unwrap_or(false));
    }

    // T5: commitment-copy — attacker re-posts victim commitment, cannot claim; victim can
    {
        let mut c = Chain::new();
        let cm = commitment_of(&s, b"vic", &a);
        c.block(0, 100, 28, vec![
            Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Commit { commitment: cm }, 0)] },
            Tx { inputs: vec![pk_in(b)], outputs: vec![carrier(&Action::Commit { commitment: cm }, 0)] }, // copy
        ]);
        // B tries claim with same salt+name -> commitment binds to B, mismatch -> drop
        c.block(1, 200, 28, vec![Tx { inputs: vec![pk_in(b)], outputs: vec![carrier(&Action::Claim { salt: s, name: b"vic".to_vec() }, 1)] }]);
        let b_failed = c.st.names.get(b"vic".as_slice()).map(|r| r.owner != b).unwrap_or(true);
        // A claims -> success
        c.block(2, 300, 28, vec![Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Claim { salt: s, name: b"vic".to_vec() }, 1)] }]);
        let a_ok = c.st.names.get(b"vic".as_slice()).map(|r| r.owner == a).unwrap_or(false);
        t.check("T5 commitment-copy attacker drop", b_failed);
        t.check("T5 commitment-copy victim mints", a_ok);
        t.check("T5 two commit rows retained", c.st.commits.len() == 2);
    }

    // T6: lapse — short lease, advance MTP past expiry -> removed, mutation stamped
    {
        let mut c = Chain::new();
        let cm = commitment_of(&s, b"laps", &a);
        c.block(0, 100, 28, vec![Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Commit { commitment: cm }, 0)] }]);
        c.block(1, 200, 28, vec![Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Claim { salt: s, name: b"laps".to_vec() }, 1)] }]); // 1 day = 86400
        // lease_expiry = MTP(1)=100 + 86400 = 86500. advance MTP beyond.
        // build 11+ blocks to push MTP > 86500
        for h in 2..14 {
            c.block(h, 100 + (h - 1) * 90000, 28, vec![]);
        }
        t.check("T6 lapsed name removed", !c.st.names.contains_key(b"laps".as_slice()));
        t.check("T6 mutation stamped", c.st.muts.contains_key(&a));
    }

    // T8: SELL price floor + listing
    {
        let mut c = mint_chain(a, b"sale", &s);
        // SELL below floor (price 2) -> ignored
        c.block(2, 300, 28, vec![Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Sell { price: 2, window: 0, name: b"sale".to_vec() }, 0)] }]);
        let not_listed = c.st.names.get(b"sale".as_slice()).map(|r| r.st == St::Owned).unwrap_or(false);
        t.check("T8 sub-floor SELL ignored", not_listed);
        // SELL at floor 3 -> listed
        c.block(3, 400, 28, vec![Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Sell { price: 3, window: 0, name: b"sale".to_vec() }, 0)] }]);
        t.check("T8 SELL lists", c.st.names.get(b"sale".as_slice()).map(|r| r.st == St::Listed && r.price == 3).unwrap_or(false));
    }

    // T9: SELL window guard — nonzero below RESERVE_WINDOW ignored
    {
        let mut c = mint_chain(a, b"win", &s);
        c.block(2, 300, 28, vec![Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Sell { price: 100, window: 1, name: b"win".to_vec() }, 0)] }]);
        t.check("T9 nonzero sub-floor window ignored", c.st.names.get(b"win".as_slice()).map(|r| r.st == St::Owned).unwrap_or(false));
    }

    // T10: escrow lock — listed name skipped by TRANSFER/RELEASE
    {
        let mut c = mint_long(a, b"lock", &s, 100);
        c.block(2, 300, 28, vec![Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Sell { price: 100000, window: 0, name: b"lock".to_vec() }, 0)] }]);
        // transfer-all to b — should skip the listed name
        c.block(3, 400, 28, vec![Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Transfer { target: b, sel: None }, 0)] }]);
        t.check("T10 listed name not transferred", c.st.names.get(b"lock".as_slice()).map(|r| r.owner == a && r.st == St::Listed).unwrap_or(false));
    }

    // T11: open market full reserve->settle
    {
        let mut c = mint_long(a, b"mkt", &s, 100);
        let price = 1_000_000u64;
        c.block(2, 300, 28, vec![Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Sell { price, window: 0, name: b"mkt".to_vec() }, 0)] }]);
        let burn_leg = (price * RESERVE_BURN_BPS / 10000).max(DUST_FLOOR);
        let pay_leg = (price * RESERVE_PAY_BPS / 10000).max(DUST_FLOOR);
        let remainder = price - burn_leg - pay_leg;
        // RESERVE by b with burn carrier value and pay_leg output to seller a
        c.block(3, 400, 28, vec![Tx {
            inputs: vec![pk_in(b)],
            outputs: vec![carrier(&Action::Reserve { name: b"mkt".to_vec() }, burn_leg), spend(a, pay_leg)],
        }]);
        let reserved = c.st.names.get(b"mkt".as_slice()).map(|r| r.st == St::Reserved && r.buyer == b).unwrap_or(false);
        t.check("T11 reserve claims option", reserved);
        // SETTLE by b with remainder output to a
        c.block(4, 500, 28, vec![Tx {
            inputs: vec![pk_in(b)],
            outputs: vec![carrier(&Action::Settle { name: b"mkt".to_vec() }, 0), spend(a, remainder)],
        }]);
        t.check("T11 settle conveys name to buyer", c.st.names.get(b"mkt".as_slice()).map(|r| r.owner == b && r.st == St::Owned).unwrap_or(false));
    }

    // T12: reserve burn-short -> drop, stays listed
    {
        let mut c = mint_long(a, b"shrt", &s, 100);
        let price = 1_000_000u64;
        c.block(2, 300, 28, vec![Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Sell { price, window: 0, name: b"shrt".to_vec() }, 0)] }]);
        let pay_leg = (price * RESERVE_PAY_BPS / 10000).max(DUST_FLOOR);
        // burn carrier value 0 (< burn_leg) -> drop
        c.block(3, 400, 28, vec![Tx {
            inputs: vec![pk_in(b)],
            outputs: vec![carrier(&Action::Reserve { name: b"shrt".to_vec() }, 0), spend(a, pay_leg)],
        }]);
        t.check("T12 burn-short reserve drops", c.st.names.get(b"shrt".as_slice()).map(|r| r.st == St::Listed).unwrap_or(false));
    }

    // T13: directed SELL_TO/PAY — stranger drop, buyer succeeds
    {
        let mut c = mint_long(a, b"dir", &s, 100);
        let price = 5000u64;
        c.block(2, 300, 28, vec![Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::SellTo { price, buyer: b, name: b"dir".to_vec() }, 0)] }]);
        let offered = c.st.names.get(b"dir".as_slice()).map(|r| r.st == St::Offered && r.buyer == b).unwrap_or(false);
        t.check("T13 sell_to offers", offered);
        // stranger c=ident(3) pays -> drop
        let stranger = ident(3);
        c.block(3, 400, 28, vec![Tx { inputs: vec![pk_in(stranger)], outputs: vec![carrier(&Action::Pay { name: b"dir".to_vec() }, 0), spend(a, price)] }]);
        t.check("T13 stranger pay drops", c.st.names.get(b"dir".as_slice()).map(|r| r.owner == a && r.st == St::Offered).unwrap_or(false));
        // buyer b pays
        c.block(4, 500, 28, vec![Tx { inputs: vec![pk_in(b)], outputs: vec![carrier(&Action::Pay { name: b"dir".to_vec() }, 0), spend(a, price)] }]);
        t.check("T13 buyer pay conveys", c.st.names.get(b"dir".as_slice()).map(|r| r.owner == b && r.st == St::Owned).unwrap_or(false));
    }

    // T14: AS repoint + OOB drop — AS 1 then CLAIM mints to vin[1]=b
    {
        let mut c = Chain::new();
        let cm = commitment_of(&s, b"asn", &b);
        c.block(0, 100, 28, vec![Tx { inputs: vec![pk_in(a), pk_in(b)], outputs: vec![carrier(&Action::Commit { commitment: cm }, 0)] }]);
        // AS 1 then CLAIM -> minted to b
        c.block(1, 200, 28, vec![Tx {
            inputs: vec![pk_in(a), pk_in(b)],
            outputs: vec![carrier(&Action::As { index: 1 }, 0), carrier(&Action::Claim { salt: s, name: b"asn".to_vec() }, 1)],
        }]);
        t.check("T14 AS repoints author", c.st.names.get(b"asn".as_slice()).map(|r| r.owner == b).unwrap_or(false));
        // OOB AS drops its segment
        let mut c2 = Chain::new();
        let cm2 = commitment_of(&s, b"oob", &a);
        c2.block(0, 100, 28, vec![Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Commit { commitment: cm2 }, 0)] }]);
        c2.block(1, 200, 28, vec![Tx {
            inputs: vec![pk_in(a)],
            outputs: vec![carrier(&Action::As { index: 9 }, 0), carrier(&Action::Claim { salt: s, name: b"oob".to_vec() }, 1)],
        }]);
        t.check("T14 OOB AS drops segment", !c2.st.names.contains_key(b"oob".as_slice()));
    }

    // T15: TRADE swap + same-block anti-rug
    {
        // a owns "ta", b owns "tb"; trade swaps.
        let mut c = Chain::new();
        let sa = [20u8; 32];
        let sb = [21u8; 32];
        let cma = commitment_of(&sa, b"ta", &a);
        let cmb = commitment_of(&sb, b"tb", &b);
        c.block(0, 100, 28, vec![
            Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Commit { commitment: cma }, 0)] },
            Tx { inputs: vec![pk_in(b)], outputs: vec![carrier(&Action::Commit { commitment: cmb }, 0)] },
        ]);
        c.block(1, 200, 28, vec![
            Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Claim { salt: sa, name: b"ta".to_vec() }, 100)] },
            Tx { inputs: vec![pk_in(b)], outputs: vec![carrier(&Action::Claim { salt: sb, name: b"tb".to_vec() }, 100)] },
        ]);
        c.block(2, 300, 28, vec![Tx {
            inputs: vec![pk_in(a), pk_in(b)],
            outputs: vec![carrier(&Action::Trade { idx_a: 0, idx_b: 1, name_a: b"ta".to_vec(), name_b: b"tb".to_vec() }, 0)],
        }]);
        let swapped = c.st.names.get(b"ta".as_slice()).map(|r| r.owner == b).unwrap_or(false)
            && c.st.names.get(b"tb".as_slice()).map(|r| r.owner == a).unwrap_or(false);
        t.check("T15 trade swaps", swapped);

        // anti-rug: a transfers "ta" away (to ident3) BEFORE the trade in same block -> trade drops
        let mut c2 = Chain::new();
        c2.block(0, 100, 28, vec![
            Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Commit { commitment: cma }, 0)] },
            Tx { inputs: vec![pk_in(b)], outputs: vec![carrier(&Action::Commit { commitment: cmb }, 0)] },
        ]);
        c2.block(1, 200, 28, vec![
            Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Claim { salt: sa, name: b"ta".to_vec() }, 100)] },
            Tx { inputs: vec![pk_in(b)], outputs: vec![carrier(&Action::Claim { salt: sb, name: b"tb".to_vec() }, 100)] },
        ]);
        let c3 = ident(3);
        c2.block(2, 300, 28, vec![
            Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Transfer { target: c3, sel: None }, 0)] },
            Tx { inputs: vec![pk_in(a), pk_in(b)], outputs: vec![carrier(&Action::Trade { idx_a: 0, idx_b: 1, name_a: b"ta".to_vec(), name_b: b"tb".to_vec() }, 0)] },
        ]);
        // ta now owned by c3; tb still b (trade dropped)
        let rug_closed = c2.st.names.get(b"ta".as_slice()).map(|r| r.owner == c3).unwrap_or(false)
            && c2.st.names.get(b"tb".as_slice()).map(|r| r.owner == b).unwrap_or(false);
        t.check("T15 same-block anti-rug drops trade", rug_closed);
    }

    // T16: no per-tx count cap — 17 COMMIT carriers all record
    {
        let mut c = Chain::new();
        let outs: Vec<Output> = (0..17)
            .map(|i| {
                let mut commitment = [0u8; 32];
                commitment[0] = i as u8;
                carrier(&Action::Commit { commitment }, 0)
            })
            .collect();
        c.block(0, 100, 28, vec![Tx { inputs: vec![pk_in(a)], outputs: outs }]);
        t.check("T16 17 COMMITs all record", c.st.commits.len() == 17);
    }

    // T17: out-of-bounds bitmap bit ignored, not fatal (RENEW with extra bits)
    {
        let mut c = mint_long(a, b"bit", &s, 50);
        // RENEW selective with flags addressing bit0 (the one owned name) + bit7 (OOB) set
        let before = c.st.names.get(b"bit".as_slice()).unwrap().lease_expiry;
        c.block(2, 300, 28, vec![Tx {
            inputs: vec![pk_in(a)],
            outputs: vec![carrier(&Action::Renew { mode: RenewMode::Selective { anchor: 1, flags: vec![0x81] } }, 10)],
        }]);
        let after = c.st.names.get(b"bit".as_slice()).unwrap().lease_expiry;
        t.check("T17 OOB bit ignored, renew applied", after > before);
    }
}

/// Charset + structural rules (§3.1): [a-z0-9-], 1..32; no leading/trailing hyphen;
/// no `--` at positions 3–4. Pins the OUTCOME behind scenario 52 / 52b.
fn dotted_names(t: &mut T) {
    t.check("hyphen name valid", valid_name(b"shib-p2p"));
    t.check("32-byte name valid", valid_name(b"abcdefghijklmnopqrstuvwxyz0123ab"));
    t.check("33-byte name invalid (max 32)", !valid_name(b"abcdefghijklmnopqrstuvwxyz0123abc"));
    t.check("dot now invalid", !valid_name(b"shib.p2p"));
    t.check("underscore now invalid", !valid_name(b"shib_p2p"));
    t.check("uppercase still invalid", !valid_name(b"Shib-p2p"));
    t.check("comma still invalid (TRADE pair split relies on it)", !valid_name(b"a,b"));
    t.check("leading hyphen invalid", !valid_name(b"-a"));
    t.check("trailing hyphen invalid", !valid_name(b"a-"));
    t.check("ACE prefix (xn--) invalid", !valid_name(b"xn--x"));

    // Fold outcome: commit+claim 'shib-p2p' (salt 0x71) and 'shib.p2p' (salt 0x74) from the
    // same author — the hyphen claim mints, the dotted claim drops (exactly 1 name total).
    let a = ident(0xAA);
    let cm_hy = commitment_of(&[0x71u8; 32], b"shib-p2p", &a);
    let cm_dot = commitment_of(&[0x74u8; 32], b"shib.p2p", &a);
    let mut st = State::new(0);
    // constant predecessor timestamps ⇒ MTP(h) == that constant (direct MTP control at h 10/11)
    st.apply_block(
        &Block { height: 10, timestamp: 1000, rate: 28, txs: vec![
            Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Commit { commitment: cm_hy }, 0)] },
            Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Commit { commitment: cm_dot }, 0)] },
        ] },
        &vec![1000i64; 10],
    );
    st.apply_block(
        &Block { height: 11, timestamp: 1500, rate: 28, txs: vec![
            Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Claim { salt: [0x71; 32], name: b"shib-p2p".to_vec() }, 10)] },
            Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Claim { salt: [0x74; 32], name: b"shib.p2p".to_vec() }, 10)] },
        ] },
        &vec![1500i64; 11],
    );
    t.check(
        "hyphen claim mints",
        st.names.get(b"shib-p2p".as_slice()).map(|r| r.owner == a && r.st == St::Owned).unwrap_or(false),
    );
    t.check(
        "dotted claim drops",
        !st.names.contains_key(b"shib.p2p".as_slice()) && st.names.len() == 1,
    );
}

/// Mint `name` to owner `a` by COMMIT(height0)+CLAIM(height1), 1-day lease. Returns chain at height1.
fn mint_chain(a: Hash160, name: &[u8], s: &[u8; 32]) -> Chain {
    mint_long(a, name, s, 1)
}
/// Mint with a `days`-day lease.
fn mint_long(a: Hash160, name: &[u8], s: &[u8; 32], days: u64) -> Chain {
    let mut c = Chain::new();
    let cm = commitment_of(s, name, &a);
    c.block(0, 100, 28, vec![Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Commit { commitment: cm }, 0)] }]);
    c.block(1, 200, 28, vec![Tx { inputs: vec![pk_in(a)], outputs: vec![carrier(&Action::Claim { salt: *s, name: name.to_vec() }, days)] }]);
    c
}

fn attrib_kats(t: &mut T) {
    // FindAndDelete KATs (fad00 boundary removal, fad01 in-body non-removal)
    // boundary removal: pattern at an opcode boundary is removed.
    let script = vec![0x51u8, 0x01, 0xAA, 0x52]; // OP_1 <push1 AA> OP_2
    let pat = vec![0x01u8, 0xAA]; // the push of AA at a boundary
    let out = find_and_delete(&script, &pat);
    t.check("fad00 boundary removal", out == vec![0x51u8, 0x52]);
    // in-body non-removal: a byte sequence that appears only inside a larger push is NOT removed
    let script2 = vec![0x03u8, 0x01, 0xAA, 0xBB]; // push3 of [01 AA BB]
    let out2 = find_and_delete(&script2, &pat);
    t.check("fad01 in-body non-removal", out2 == script2);
    // load-bearing: with vs without FaD differ on a boundary-containing scriptCode
    // (we just confirm find_and_delete changes the bytes when the pattern is at a boundary)
    t.check("fad load-bearing differ", find_and_delete(&script, &pat) != script);

    // ----- raw-tx attribution (§4) -----
    // Build a P2PKH spend with a strict-DER low-S sig (hashtype 0x01) and a canonical pubkey.
    let mut der = vec![0x30u8, 0x44, 0x02, 0x20];
    der.extend_from_slice(&[0x10u8; 32]); // R (high bit clear, no pad)
    der.push(0x02);
    der.push(0x20);
    der.extend_from_slice(&[0x10u8; 32]); // S (small → low-S)
    let mut sig = der.clone();
    sig.push(0x01); // SIGHASH_ALL
    let mut pk = vec![0x02u8];
    pk.extend_from_slice(&[0x11u8; 32]); // X < p
    let mut scriptsig = Vec::new();
    scriptsig.push(sig.len() as u8);
    scriptsig.extend_from_slice(&sig);
    scriptsig.push(pk.len() as u8);
    scriptsig.extend_from_slice(&pk);
    let raw = build_raw_tx(&scriptsig);
    let parsed = parse_tx(&raw);
    t.check("attrib tx parses", parsed.is_some());
    if let Some(tx) = parsed {
        let at = attribute(&tx, 0);
        t.check("attrib P2PKH classified (status>=2)", at.status >= 2);
        t.check("attrib identity = hash160(pubkey)", at.identity == hash160(&pk));
        // determinism: same input → same attribution
        let at2 = attribute(&tx, 0);
        t.check("attrib deterministic", at == at2);
    }
    // A7 regression: a well-encoded but OFF-CURVE P2PKH pubkey is on-curve-drop (status 1) —
    // carrying the real identity+sighash, NOT routed through verify(). (Matches impls/c attrib.c;
    // the earlier redeemScript-only reading was the clean-room's consensus-fork divergence.)
    {
        let mut offpk: Option<Vec<u8>> = None;
        for i in 1u32..200_000 {
            let mut cand = vec![0x02u8];
            let mut x = [0u8; 32];
            x[0..4].copy_from_slice(&i.to_le_bytes()); // X = i (< p) ⇒ canonical encoding
            cand.extend_from_slice(&x);
            if !on_curve(&cand) {
                offpk = Some(cand);
                break;
            }
        }
        t.check("A7: found an off-curve canonical pubkey", offpk.is_some());
        if let Some(pk_off) = offpk {
            let mut ss = Vec::new();
            ss.push(sig.len() as u8);
            ss.extend_from_slice(&sig);
            ss.push(pk_off.len() as u8);
            ss.extend_from_slice(&pk_off);
            if let Some(tx) = parse_tx(&build_raw_tx(&ss)) {
                let at = attribute(&tx, 0);
                t.check("A7: off-curve P2PKH → status 1 (on-curve-drop)", at.status == 1);
                t.check("A7: on-curve-drop carries identity", at.identity == hash160(&pk_off));
                t.check("A7: on-curve-drop carries sighash", at.sighash != [0u8; 32]);
            }
        }
    }
    // malformed scriptSig (single trailing opcode) → classify-drop status 0
    let bad_ss = vec![0xACu8]; // OP_CHECKSIG, not a push
    let raw_bad = build_raw_tx(&bad_ss);
    if let Some(tx) = parse_tx(&raw_bad) {
        t.check("attrib malformed → status 0", attribute(&tx, 0).status == 0);
    }
    // truncated raw tx → parse fails (contributes 0xFF to the digest, never panics)
    t.check("attrib truncated tx → None", parse_tx(&raw[..raw.len() - 3]).is_none());
}

/// Build a minimal raw legacy tx with one input carrying `scriptsig` and one P2PKH-ish output.
fn build_raw_tx(scriptsig: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&1u32.to_le_bytes()); // version
    v.push(0x01); // 1 input
    v.extend_from_slice(&[0u8; 36]); // prevout
    v.push(scriptsig.len() as u8);
    v.extend_from_slice(scriptsig);
    v.extend_from_slice(&0xffffffffu32.to_le_bytes()); // sequence
    v.push(0x01); // 1 output
    v.extend_from_slice(&1000u64.to_le_bytes()); // value
    v.push(0x19); // spk len 25
    v.extend_from_slice(&[0x76, 0xa9, 0x14]);
    v.extend_from_slice(&[0u8; 20]);
    v.extend_from_slice(&[0x88, 0xac]);
    v.extend_from_slice(&0u32.to_le_bytes()); // locktime
    v
}
