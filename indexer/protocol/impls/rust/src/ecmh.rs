//! §13.2 — the pinned, portable ECMH primitive vector set (`sm ecmh`).
//!
//! Faithful port of impls/c/src/ecmh.c (`ecmh_cmd`). Prints output byte-identical
//! to the C reference: hash-to-curve KATs over fixed preimages, identity (∞)
//! serialization, a tagged multiset sum (asserted commutative + pinned), and an
//! inverse round-trip — all folded into one cross-language `combined` digest.
//! Names-only: three domain tags (name/commit/mut).

use crate::secp256k1::{secp_ecmh_add, secp_ecmh_hash, secp_ecmh_identity, secp_ecmh_negate};
use crate::sha256::Sha256;

const HEXD: &[u8; 16] = b"0123456789abcdef";
fn puthex(out: &mut String, d: &[u8]) {
    for &b in d {
        out.push(HEXD[(b >> 4) as usize] as char);
        out.push(HEXD[(b & 15) as usize] as char);
    }
}

// domain tags — second-preimage separation between tables.
const TAG_NAME: u8 = 0x01;
const TAG_COMMIT: u8 = 0x02;
const TAG_MUT: u8 = 0x04;
const ECMH_REC_TAG: [u8; 6] = [b'E', b'C', b'M', b'H', b'v', b'1'];

// P(rec) = H2C("ECMHv1" ‖ tag ‖ body).
fn rec_point(tag: u8, body: &[u8]) -> [u8; 33] {
    let mut pre = Vec::with_capacity(7 + body.len());
    pre.extend_from_slice(&ECMH_REC_TAG);
    pre.push(tag);
    pre.extend_from_slice(body);
    let (_ctr, pt) = secp_ecmh_hash(&pre);
    pt
}

pub fn run() -> i32 {
    let mut comb = Sha256::new();
    let mut line = String::new();

    // version self-doc
    println!("ecmh ECMHv1");
    comb.update(b"ECMHv1");

    // 1. hash-to-curve KAT — fixed preimages → (ctr, compressed even-Y point).
    let h2c: [(&str, &[u8]); 4] = [
        ("empty", b""),
        ("a", b"a"),
        ("pepe", b"pepenet"),
        ("doge", b"doge"),
    ];
    let ff = [0xFFu8; 32];
    let z32 = [0u8; 32];
    let mut kat: Vec<(&str, &[u8])> = h2c.to_vec();
    kat.push(("ff32", &ff));
    kat.push(("z32", &z32));
    for (label, pre) in &kat {
        let (ctr, pt) = secp_ecmh_hash(pre);
        line.clear();
        puthex(&mut line, &pt);
        println!("h2c {} ctr={} pt={}", label, ctr, line);
        comb.update(&[ctr as u8]);
        comb.update(&pt);
    }

    // 2. identity (∞) serialization
    let id = secp_ecmh_identity();
    line.clear();
    puthex(&mut line, &id);
    println!("identity {}", line);
    comb.update(&id);

    // 3. tagged multiset sum — a fixed set of (tag ‖ row) records, summed two ways.
    let recs: [(u8, &[u8]); 4] = [
        (TAG_NAME, b"\x03foo"),
        (TAG_NAME, b"\x03bar"),
        (TAG_COMMIT, b"commitment-blob-32-bytes-xxxxxx"),
        (TAG_MUT, b"owner-mutation"),
    ];
    let mut fwd = secp_ecmh_identity();
    let mut rev = secp_ecmh_identity();
    for (tag, body) in recs.iter() {
        let pt = rec_point(*tag, body);
        secp_ecmh_add(&mut fwd, &pt);
    }
    for (tag, body) in recs.iter().rev() {
        let pt = rec_point(*tag, body);
        secp_ecmh_add(&mut rev, &pt);
    }
    let commut = (fwd == rev) as u8;
    line.clear();
    puthex(&mut line, &fwd);
    println!("sum {}", line);
    println!("commutative {}", commut);
    comb.update(&fwd);
    comb.update(&[commut]);

    // 4. inverse — remove the first record from the sum, re-add, must round-trip.
    {
        let pt0 = rec_point(recs[0].0, recs[0].1);
        let mut acc = fwd;
        let mut npt = pt0;
        secp_ecmh_negate(&mut npt);
        secp_ecmh_add(&mut acc, &npt); // remove rec[0]
        secp_ecmh_add(&mut acc, &pt0); // re-add rec[0]
        let roundtrip = (acc == fwd) as u8;
        println!("inverse_roundtrip {}", roundtrip);
        comb.update(&[roundtrip]);
    }

    let cd = comb.finalize();
    line.clear();
    puthex(&mut line, &cd);
    println!("combined {}", line);
    0
}
