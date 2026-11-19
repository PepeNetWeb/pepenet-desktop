//! §4 Strategy B — the pinned ECDSA curve-vector set (`sm attrib-curve`).
//!
//! Faithful port of impls/c/src/attrib_curve.c (`attrib_cmd_curve`) + the end-to-end
//! pipeline in attrib.c (`attrib_real_endtoend`). Prints output byte-identical to the
//! C reference: pinned P/N/N_HALF constants, on-curve edge vectors, RFC-6979
//! deterministic (r,s)+canonical-DER, the verify boundary battery, the tiny-key KAT,
//! the PRIMARY `combined` digest, then the real-curve end-to-end vectors + `combined_e2e`.

use crate::attrib::{attribute, legacy_sighash, parse_tx, set_real_curve, ParsedTx, TxIn, TxOut};
use crate::ripemd160::hash160;
use crate::secp256k1::{secp_ecdsa_sign, secp_ecdsa_verify, secp_on_curve, secp_pubkey};
use crate::sha256::Sha256;

const HEXD: &[u8; 16] = b"0123456789abcdef";
fn puthex(out: &mut String, d: &[u8]) {
    for &b in d {
        out.push(HEXD[(b >> 4) as usize] as char);
        out.push(HEXD[(b & 15) as usize] as char);
    }
}
fn sha(d: &[u8]) -> [u8; 32] {
    let mut c = Sha256::new();
    c.update(d);
    c.finalize()
}

// secp256k1 p, n, n/2, G — big-endian constants (mirror secp256k1.c).
const CV_P: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
];
const CV_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];
const CV_NHALF: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];
const CV_GX: [u8; 32] = [
    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
    0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
];
const CV_GY: [u8; 32] = [
    0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
    0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8,
];

// canonical strict-DER (r,s) ‖ SIGHASH_ALL.
fn der_int(out: &mut Vec<u8>, v: &[u8; 32]) {
    let mut i = 0usize;
    while i < 31 && v[i] == 0 {
        i += 1;
    }
    let len = 32 - i;
    let pad = if v[i] & 0x80 != 0 { 1 } else { 0 };
    out.push(0x02);
    out.push((len + pad) as u8);
    if pad == 1 {
        out.push(0x00);
    }
    out.extend_from_slice(&v[i..]);
}
fn der_sig(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    let mut body = Vec::new();
    der_int(&mut body, r);
    der_int(&mut body, s);
    let mut out = Vec::with_capacity(body.len() + 3);
    out.push(0x30);
    out.push(body.len() as u8);
    out.extend_from_slice(&body);
    out.push(0x01); // SIGHASH_ALL
    out
}

pub fn run() -> i32 {
    let mut comb = Sha256::new();
    let mut line = String::new();

    // ── 1. pinned constants ────────────────────────────────────────────────────
    line.clear();
    line.push_str("p ");
    puthex(&mut line, &CV_P);
    println!("{}", line);
    comb.update(&CV_P);
    line.clear();
    line.push_str("n ");
    puthex(&mut line, &CV_N);
    println!("{}", line);
    comb.update(&CV_N);
    line.clear();
    line.push_str("nhalf ");
    puthex(&mut line, &CV_NHALF);
    println!("{}", line);
    comb.update(&CV_NHALF);

    // ── 2. on-curve membership at the edges ────────────────────────────────────
    let mut oc: Vec<(&str, Vec<u8>)> = Vec::new();
    // G uncompressed (on)
    {
        let mut b = vec![0x04u8];
        b.extend_from_slice(&CV_GX);
        b.extend_from_slice(&CV_GY);
        oc.push(("oc_G_uncomp", b));
    }
    // G compressed even (on)
    {
        let mut b = vec![0x02u8];
        b.extend_from_slice(&CV_GX);
        oc.push(("oc_G_comp02", b));
    }
    // G compressed odd-prefix (still on curve)
    {
        let mut b = vec![0x03u8];
        b.extend_from_slice(&CV_GX);
        oc.push(("oc_G_comp03", b));
    }
    // (Gx, Gy^lsb) uncompressed (off curve)
    {
        let mut b = vec![0x04u8];
        b.extend_from_slice(&CV_GX);
        b.extend_from_slice(&CV_GY);
        let l = b.len();
        b[l - 1] ^= 0x01;
        oc.push(("oc_G_badY", b));
    }
    // compressed X=0
    {
        let mut b = vec![0x02u8];
        b.extend_from_slice(&[0u8; 32]);
        oc.push(("oc_X0", b));
    }
    // compressed X=1
    {
        let mut b = vec![0x02u8];
        let mut x = [0u8; 32];
        x[31] = 1;
        b.extend_from_slice(&x);
        oc.push(("oc_X1", b));
    }
    // uncompressed X>=p (X = p)
    {
        let mut b = vec![0x04u8];
        b.extend_from_slice(&CV_P);
        b.extend_from_slice(&CV_GY);
        oc.push(("oc_Xeqp", b));
    }
    // compressed X>=p
    {
        let mut b = vec![0x02u8];
        b.extend_from_slice(&CV_P);
        oc.push(("oc_comp_Xeqp", b));
    }
    // bad prefix 0x05
    {
        let mut b = vec![0x05u8];
        b.extend_from_slice(&CV_GX);
        oc.push(("oc_badprefix", b));
    }
    for (name, key) in &oc {
        let v = secp_on_curve(key) as i32;
        println!("{} {}", name, v);
        comb.update(&[v as u8]);
        comb.update(key);
    }

    // ── 3 & 4. RFC-6979 deterministic sign + ECDSA verify at the boundaries ─────
    for i in 0..4 {
        let mut priv_ = [0u8; 32];
        priv_[28] = 0xC0;
        priv_[29] = 0xFF;
        priv_[30] = 0xEE;
        priv_[31] = 0x10 + i as u8;
        let pubk = match secp_pubkey(&priv_) {
            Some(p) => p,
            None => {
                println!("sig{} PUBFAIL", i);
                continue;
            }
        };
        let m = format!("strategy-b curve vector {}", i);
        let h = sha(m.as_bytes());
        let (r, s) = match secp_ecdsa_sign(&priv_, &h) {
            Some(rs) => rs,
            None => {
                println!("sig{} SIGNFAIL", i);
                continue;
            }
        };
        let der = der_sig(&r, &s);
        line.clear();
        line.push_str(&format!("sig{} pub=", i));
        puthex(&mut line, &pubk);
        line.push_str(" r=");
        puthex(&mut line, &r);
        line.push_str(" s=");
        puthex(&mut line, &s);
        line.push_str(" der=");
        puthex(&mut line, &der);
        println!("{}", line);
        comb.update(&pubk);
        comb.update(&r);
        comb.update(&s);
        comb.update(&der);

        // verify boundary battery
        let zero = [0u8; 32];
        let mut hbad = h;
        hbad[0] ^= 0x01;
        // high-S = n - s (byte subtraction)
        let mut his = [0u8; 32];
        {
            let mut borrow: i32 = 0;
            for k in (0..32).rev() {
                let mut d = CV_N[k] as i32 - s[k] as i32 - borrow;
                if d < 0 {
                    d += 256;
                    borrow = 1;
                } else {
                    borrow = 0;
                }
                his[k] = d as u8;
            }
        }
        let mut wrongpub = pubk;
        wrongpub[0] ^= 0x01;
        let vt: [(&str, &[u8; 32], &[u8; 32], &[u8; 32], &[u8]); 8] = [
            ("valid", &h, &r, &s, &pubk),
            ("tamper", &hbad, &r, &s, &pubk),
            ("r0", &h, &zero, &s, &pubk),
            ("s0", &h, &r, &zero, &pubk),
            ("rN", &h, &CV_N, &s, &pubk),
            ("sN", &h, &r, &CV_N, &pubk),
            ("highS", &h, &r, &his, &pubk),
            ("wrongpk", &h, &r, &s, &wrongpub),
        ];
        line.clear();
        line.push_str(&format!("ver{}", i));
        for (nm, hh, rr, ss, pk) in vt.iter() {
            let v = secp_ecdsa_verify(hh, rr, ss, pk) as i32;
            line.push_str(&format!(" {}={}", nm, v));
            comb.update(&[v as u8]);
        }
        println!("{}", line);
    }

    // ── 5. tiny-key KAT: priv=1 ⇒ G ; priv=2 ⇒ 2G ──────────────────────────────
    {
        let mut p1 = [0u8; 32];
        p1[31] = 1;
        let pk1 = secp_pubkey(&p1).unwrap();
        line.clear();
        line.push_str("priv1_pub=");
        puthex(&mut line, &pk1);
        println!("{}", line);
        comb.update(&pk1);
        let mut p2 = [0u8; 32];
        p2[31] = 2;
        let pk2 = secp_pubkey(&p2).unwrap();
        line.clear();
        line.push_str("priv2_pub=");
        puthex(&mut line, &pk2);
        println!("{}", line);
        comb.update(&pk2);
    }

    // PRIMARY cross-language digest (sections 1–5).
    let cd = comb.finalize();
    line.clear();
    line.push_str("combined ");
    puthex(&mut line, &cd);
    println!("{}", line);

    // ── 6. end-to-end with the real curve ──────────────────────────────────────
    let mut e2e = Sha256::new();
    real_endtoend(&mut e2e);
    let ed = e2e.finalize();
    line.clear();
    line.push_str("combined_e2e ");
    puthex(&mut line, &ed);
    println!("{}", line);

    0
}

// ── raw-tx byte builders (mirror attrib.c e2e_rawtx / emit_push) ──────────────
fn put_varint(out: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}
fn emit_push(out: &mut Vec<u8>, data: &[u8]) {
    let l = data.len();
    if l < 76 {
        out.push(l as u8);
    } else if l < 256 {
        out.push(0x4c);
        out.push(l as u8);
    } else {
        out.push(0x4d);
        out.extend_from_slice(&(l as u16).to_le_bytes());
    }
    out.extend_from_slice(data);
}
// raw tx: version 1, 1 input (outpoint 0x11.., seq FFFFFFFF), 1 output (value 100000,
// scriptPubKey = OP_RETURN), locktime 0.
fn e2e_rawtx(ss: &[u8]) -> Vec<u8> {
    let mut raw = Vec::new();
    raw.extend_from_slice(&1u32.to_le_bytes());
    put_varint(&mut raw, 1);
    raw.extend_from_slice(&[0x11u8; 36]);
    put_varint(&mut raw, ss.len() as u64);
    raw.extend_from_slice(ss);
    raw.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    put_varint(&mut raw, 1);
    raw.extend_from_slice(&100000u64.to_le_bytes());
    put_varint(&mut raw, 1);
    raw.push(0x6a);
    raw.extend_from_slice(&0u32.to_le_bytes());
    raw
}
// skeleton ParsedTx matching e2e_rawtx structure (empty scriptsig); used for sighash.
fn e2e_skeleton() -> ParsedTx {
    ParsedTx {
        version: 1,
        vin: vec![TxIn { prevout: [0x11u8; 36], scriptsig: Vec::new(), sequence: 0xFFFF_FFFF }],
        vout: vec![TxOut { value: 100000, spk: vec![0x6a] }],
        locktime: 0,
    }
}

fn emit_e2e(comb: &mut Sha256, name: &str, tx: &ParsedTx, k: usize) {
    let res = attribute(tx, k);
    let mut idh = String::new();
    puthex(&mut idh, &res.identity);
    println!("{} {}:{}", name, res.status, idh);
    comb.update(&[res.status]);
    comb.update(&res.sighash);
    comb.update(&res.identity);
}

fn real_endtoend(comb: &mut Sha256) {
    set_real_curve(true);

    // ── A. P2PKH, correctly signed ⇒ FOUND ─────────────────────────────────────
    {
        let mut priv_ = [0u8; 32];
        priv_[31] = 0x2A;
        let pubk = secp_pubkey(&priv_).unwrap();
        let h160 = hash160(&pubk);
        let mut sc = Vec::new();
        sc.extend_from_slice(&[0x76, 0xa9, 0x14]);
        sc.extend_from_slice(&h160);
        sc.extend_from_slice(&[0x88, 0xac]);
        let sk = e2e_skeleton();
        let sh = legacy_sighash(&sk, 0, &sc);
        let (r, s) = secp_ecdsa_sign(&priv_, &sh).unwrap();
        let der = der_sig(&r, &s);
        let mut ss = Vec::new();
        emit_push(&mut ss, &der);
        emit_push(&mut ss, &pubk);
        let raw = e2e_rawtx(&ss);
        match parse_tx(&raw) {
            Some(t) => emit_e2e(comb, "e2e_p2pkh_valid", &t, 0),
            None => println!("e2e_p2pkh_valid PARSEFAIL"),
        }
    }
    // ── B. P2PKH, signed by the WRONG key ⇒ verify-drop (status 2) ─────────────
    {
        let mut priv_ = [0u8; 32];
        priv_[31] = 0x2A;
        let mut wrong = [0u8; 32];
        wrong[31] = 0x2B;
        let pubk = secp_pubkey(&priv_).unwrap();
        let h160 = hash160(&pubk);
        let mut sc = Vec::new();
        sc.extend_from_slice(&[0x76, 0xa9, 0x14]);
        sc.extend_from_slice(&h160);
        sc.extend_from_slice(&[0x88, 0xac]);
        let sk = e2e_skeleton();
        let sh = legacy_sighash(&sk, 0, &sc);
        let (r, s) = secp_ecdsa_sign(&wrong, &sh).unwrap();
        let der = der_sig(&r, &s);
        let mut ss = Vec::new();
        emit_push(&mut ss, &der);
        emit_push(&mut ss, &pubk);
        let raw = e2e_rawtx(&ss);
        match parse_tx(&raw) {
            Some(t) => emit_e2e(comb, "e2e_p2pkh_wrongkey", &t, 0),
            None => println!("e2e_p2pkh_wrongkey PARSEFAIL"),
        }
    }
    // ── C. 2-of-2 P2SH multisig, two correct in-order sigs ⇒ FOUND ─────────────
    {
        let mut privs = [[0u8; 32]; 2];
        let mut pubs = [[0u8; 33]; 2];
        for i in 0..2 {
            privs[i][31] = 0x50 + i as u8;
            pubs[i] = secp_pubkey(&privs[i]).unwrap();
        }
        let mut rs = Vec::new();
        rs.push(0x52); // OP_2
        for i in 0..2 {
            rs.push(0x21);
            rs.extend_from_slice(&pubs[i]);
        }
        rs.push(0x52); // OP_2
        rs.push(0xae); // OP_CHECKMULTISIG
        let sk = e2e_skeleton();
        let sh = legacy_sighash(&sk, 0, &rs);
        let mut ss = Vec::new();
        ss.push(0x00); // NULLDUMMY
        for i in 0..2 {
            let (r, s) = secp_ecdsa_sign(&privs[i], &sh).unwrap();
            let der = der_sig(&r, &s);
            emit_push(&mut ss, &der);
        }
        emit_push(&mut ss, &rs);
        let raw = e2e_rawtx(&ss);
        match parse_tx(&raw) {
            Some(t) => emit_e2e(comb, "e2e_multisig_valid", &t, 0),
            None => println!("e2e_multisig_valid PARSEFAIL"),
        }
    }

    set_real_curve(false);
}
