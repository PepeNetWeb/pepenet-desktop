//! §4 Strategy B — real secp256k1 (self-rolled, zero external crates).
//!
//! A faithful port of impls/c/src/secp256k1.c: field arithmetic mod
//! p = 2^256 − 2^32 − 977 (4×u64 limbs, fast fold-reduction via u128 products),
//! Jacobian point ops + double-and-add scalar multiply, pubkey decode / on-curve,
//! scalar arithmetic mod n (binary-egcd inverse; schoolbook mulmod with bitwise
//! reduce), HMAC-SHA256 + RFC-6979 deterministic nonce + ECDSA sign/verify.
//!
//! Correctness, not speed; nothing here is constant time. Limbs are little-endian:
//! value = v[0] + v[1]·2^64 + v[2]·2^128 + v[3]·2^192.

use crate::sha256::Sha256;

// p = 2^256 − 2^32 − 977 ; little-endian limbs.
const FE_P: [u64; 4] = [
    0xFFFF_FFFE_FFFF_FC2F,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
];
const FE_C: u64 = 0x1_0000_03D1; // 2^256 mod p = 2^32 + 977

const SECP_N_BE: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];
const SECP_N_HALF_BE: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];
const SECP_GX_BE: [u8; 32] = [
    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
    0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
];
const SECP_GY_BE: [u8; 32] = [
    0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
    0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8,
];

// ── 256-bit helpers (limb arrays, little-endian) ──────────────────────────────
fn be32_to_limbs(b: &[u8; 32]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for i in 0..4 {
        let mut w = 0u64;
        for j in 0..8 {
            w = (w << 8) | b[i * 8 + j] as u64;
        }
        out[3 - i] = w; // b[0..7] = most significant
    }
    out
}
fn limbs_to_be32(inp: &[u64; 4]) -> [u8; 32] {
    let mut b = [0u8; 32];
    for i in 0..4 {
        let w = inp[3 - i];
        for j in 0..8 {
            b[i * 8 + j] = (w >> (56 - 8 * j)) as u8;
        }
    }
    b
}
fn limb_cmp(a: &[u64; 4], b: &[u64; 4]) -> i32 {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return if a[i] < b[i] { -1 } else { 1 };
        }
    }
    0
}
fn limb_is_zero(a: &[u64; 4]) -> bool {
    (a[0] | a[1] | a[2] | a[3]) == 0
}

// ── field element ──────────────────────────────────────────────────────────────
#[derive(Clone, Copy)]
struct Fe {
    v: [u64; 4],
}

fn fe_is_zero(a: &Fe) -> bool {
    limb_is_zero(&a.v)
}
fn fe_eq(a: &Fe, b: &Fe) -> bool {
    limb_cmp(&a.v, &b.v) == 0
}
fn fe_is_odd(a: &Fe) -> bool {
    (a.v[0] & 1) == 1
}
fn fe_p() -> Fe {
    Fe { v: FE_P }
}

fn fe_cond_sub_p(a: &mut Fe) {
    while limb_cmp(&a.v, &FE_P) >= 0 {
        let mut borrow: u128 = 0;
        for i in 0..4 {
            let x = (a.v[i] as u128).wrapping_sub(FE_P[i] as u128).wrapping_sub(borrow);
            a.v[i] = x as u64;
            borrow = (x >> 64) & 1;
        }
    }
}
fn fe_add(a: &Fe, b: &Fe) -> Fe {
    let mut r = Fe { v: [0; 4] };
    let mut carry: u128 = 0;
    for i in 0..4 {
        let x = a.v[i] as u128 + b.v[i] as u128 + carry;
        r.v[i] = x as u64;
        carry = x >> 64;
    }
    if carry != 0 {
        let c = FE_C as u128 * carry as u64 as u128;
        let mut x = r.v[0] as u128 + (c as u64) as u128;
        r.v[0] = x as u64;
        let mut cc = (x >> 64) as u64;
        x = r.v[1] as u128 + ((c >> 64) as u64) as u128 + cc as u128;
        r.v[1] = x as u64;
        cc = (x >> 64) as u64;
        x = r.v[2] as u128 + cc as u128;
        r.v[2] = x as u64;
        cc = (x >> 64) as u64;
        x = r.v[3] as u128 + cc as u128;
        r.v[3] = x as u64;
    }
    fe_cond_sub_p(&mut r);
    r
}
fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    let mut r = Fe { v: [0; 4] };
    let mut borrow: u128 = 0;
    for i in 0..4 {
        let x = (a.v[i] as u128).wrapping_sub(b.v[i] as u128).wrapping_sub(borrow);
        r.v[i] = x as u64;
        borrow = (x >> 64) & 1;
    }
    if borrow != 0 {
        let mut carry: u128 = 0;
        for i in 0..4 {
            let x = r.v[i] as u128 + FE_P[i] as u128 + carry;
            r.v[i] = x as u64;
            carry = x >> 64;
        }
    }
    r
}
// reduce an 8-limb (512-bit) product mod p.
fn fe_reduce(t: &[u64; 8]) -> Fe {
    let mut low = [t[0], t[1], t[2], t[3], 0u64];
    let mut carry: u128 = 0;
    for i in 0..4 {
        let x = t[4 + i] as u128 * FE_C as u128 + low[i] as u128 + carry;
        low[i] = x as u64;
        carry = x >> 64;
    }
    low[4] = low[4].wrapping_add(carry as u64);
    while low[4] != 0 {
        let h = low[4];
        low[4] = 0;
        let c = h as u128 * FE_C as u128;
        let mut x = low[0] as u128 + (c as u64) as u128;
        low[0] = x as u64;
        let mut cc = (x >> 64) as u64;
        x = low[1] as u128 + ((c >> 64) as u64) as u128 + cc as u128;
        low[1] = x as u64;
        cc = (x >> 64) as u64;
        x = low[2] as u128 + cc as u128;
        low[2] = x as u64;
        cc = (x >> 64) as u64;
        x = low[3] as u128 + cc as u128;
        low[3] = x as u64;
        cc = (x >> 64) as u64;
        low[4] = cc;
    }
    let mut r = Fe { v: [low[0], low[1], low[2], low[3]] };
    fe_cond_sub_p(&mut r);
    r
}
fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    let mut t = [0u64; 8];
    for i in 0..4 {
        let mut carry: u128 = 0;
        for j in 0..4 {
            let x = a.v[i] as u128 * b.v[j] as u128 + t[i + j] as u128 + carry;
            t[i + j] = x as u64;
            carry = x >> 64;
        }
        t[i + 4] = t[i + 4].wrapping_add(carry as u64);
    }
    fe_reduce(&t)
}
fn fe_sqr(a: &Fe) -> Fe {
    fe_mul(a, a)
}
fn fe_set_u64(x: u64) -> Fe {
    Fe { v: [x, 0, 0, 0] }
}

// r = a^exp mod p, exp as 32 big-endian bytes.
fn fe_pow(a: &Fe, exp_be: &[u8; 32]) -> Fe {
    let mut acc = fe_set_u64(1);
    for &byte in exp_be.iter() {
        for bit in (0..8).rev() {
            acc = fe_sqr(&acc);
            if (byte >> bit) & 1 == 1 {
                acc = fe_mul(&acc, a);
            }
        }
    }
    acc
}
fn fe_inv(a: &Fe) -> Fe {
    const P_MINUS_2: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2D,
    ];
    fe_pow(a, &P_MINUS_2)
}
fn fe_sqrt(a: &Fe) -> Fe {
    const P_PLUS_1_DIV4: [u8; 32] = [
        0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBF, 0xFF, 0xFF, 0x0C,
    ];
    fe_pow(a, &P_PLUS_1_DIV4)
}

// ── points (Jacobian: affine = (X/Z^2, Y/Z^3); Z==0 ⇒ infinity) ──────────────
#[derive(Clone, Copy)]
struct Jac {
    x: Fe,
    y: Fe,
    z: Fe,
    inf: bool,
}

fn jac_set_inf() -> Jac {
    Jac { x: fe_set_u64(1), y: fe_set_u64(1), z: fe_set_u64(0), inf: true }
}

fn jac_double(p: &Jac) -> Jac {
    if p.inf || fe_is_zero(&p.y) {
        return jac_set_inf();
    }
    let a = fe_sqr(&p.x); // A = X^2
    let b = fe_sqr(&p.y); // B = Y^2
    let c = fe_sqr(&b); // C = B^2
    let mut t = fe_add(&p.x, &b);
    t = fe_sqr(&t); // (X+B)^2
    t = fe_sub(&t, &a);
    t = fe_sub(&t, &c); // (X+B)^2 - A - C
    let d = fe_add(&t, &t); // D = 2·(...)
    let mut e = fe_add(&a, &a);
    e = fe_add(&e, &a); // E = 3A
    let f = fe_sqr(&e); // F = E^2
    let mut x3 = fe_sub(&f, &d);
    x3 = fe_sub(&x3, &d); // X3 = F - 2D
    t = fe_sub(&d, &x3);
    t = fe_mul(&e, &t); // E·(D - X3)
    let mut t2 = fe_add(&c, &c);
    t2 = fe_add(&t2, &t2);
    t2 = fe_add(&t2, &t2); // 8C
    let y3 = fe_sub(&t, &t2); // Y3 = E·(D-X3) - 8C
    let mut z3 = fe_mul(&p.y, &p.z);
    z3 = fe_add(&z3, &z3); // Z3 = 2·Y·Z (read p.y/z before write — locals make this safe)
    Jac { x: x3, y: y3, z: z3, inf: false }
}
fn jac_add(p: &Jac, q: &Jac) -> Jac {
    if p.inf {
        return *q;
    }
    if q.inf {
        return *p;
    }
    let z1z1 = fe_sqr(&p.z);
    let z2z2 = fe_sqr(&q.z);
    let u1 = fe_mul(&p.x, &z2z2);
    let u2 = fe_mul(&q.x, &z1z1);
    let mut s1 = fe_mul(&p.y, &q.z);
    s1 = fe_mul(&s1, &z2z2); // S1 = Y1·Z2^3
    let mut s2 = fe_mul(&q.y, &p.z);
    s2 = fe_mul(&s2, &z1z1); // S2 = Y2·Z1^3
    if fe_eq(&u1, &u2) {
        if !fe_eq(&s1, &s2) {
            return jac_set_inf(); // P + (−P)
        }
        return jac_double(p); // P == Q
    }
    let h = fe_sub(&u2, &u1);
    let r = fe_sub(&s2, &s1);
    let hh = fe_sqr(&h);
    let hhh = fe_mul(&h, &hh);
    let v = fe_mul(&u1, &hh);
    let mut t = fe_sqr(&r);
    t = fe_sub(&t, &hhh);
    let t2 = fe_add(&v, &v);
    let x3 = fe_sub(&t, &t2); // X3 = R^2 - HHH - 2V
    let mut tt = fe_sub(&v, &x3);
    tt = fe_mul(&r, &tt);
    let t2b = fe_mul(&s1, &hhh);
    let y3 = fe_sub(&tt, &t2b); // Y3 = R·(V-X3) - S1·HHH
    let tz = fe_mul(&p.z, &q.z);
    let z3 = fe_mul(&tz, &h); // Z3 = Z1·Z2·H
    Jac { x: x3, y: y3, z: z3, inf: false }
}
// R = scalar·P, scalar as 32 big-endian bytes (double-and-add, MSB first).
fn jac_mul(p: &Jac, k_be: &[u8; 32]) -> Jac {
    let mut acc = jac_set_inf();
    for &byte in k_be.iter() {
        for bit in (0..8).rev() {
            acc = jac_double(&acc);
            if (byte >> bit) & 1 == 1 {
                acc = jac_add(&acc, p);
            }
        }
    }
    acc
}
// affine X,Y from a non-infinity Jacobian point.
fn jac_affine(p: &Jac) -> Option<(Fe, Fe)> {
    if p.inf || fe_is_zero(&p.z) {
        return None;
    }
    let zinv = fe_inv(&p.z);
    let zinv2 = fe_sqr(&zinv);
    let zinv3 = fe_mul(&zinv2, &zinv);
    let x = fe_mul(&p.x, &zinv2);
    let y = fe_mul(&p.y, &zinv3);
    Some((x, y))
}
fn jac_from_affine(x: &Fe, y: &Fe) -> Jac {
    Jac { x: *x, y: *y, z: fe_set_u64(1), inf: false }
}
fn secp_g() -> Jac {
    let gx = Fe { v: be32_to_limbs(&SECP_GX_BE) };
    let gy = Fe { v: be32_to_limbs(&SECP_GY_BE) };
    jac_from_affine(&gx, &gy)
}

// ── pubkey decode + on-curve ──────────────────────────────────────────────────
fn fe_from_be_lt_p(b: &[u8; 32]) -> Option<Fe> {
    let r = Fe { v: be32_to_limbs(b) };
    if limb_cmp(&r.v, &FE_P) < 0 {
        Some(r)
    } else {
        None
    }
}
fn rhs_curve(x: &Fe) -> Fe {
    let x2 = fe_sqr(x);
    let x3 = fe_mul(&x2, x);
    let seven = fe_set_u64(7);
    fe_add(&x3, &seven)
}
fn pub_decode(pub_: &[u8]) -> Option<(Fe, Fe)> {
    let plen = pub_.len();
    if plen == 33 && (pub_[0] == 0x02 || pub_[0] == 0x03) {
        let mut xb = [0u8; 32];
        xb.copy_from_slice(&pub_[1..33]);
        let x = fe_from_be_lt_p(&xb)?;
        let rhs = rhs_curve(&x);
        let mut beta = fe_sqrt(&rhs);
        let beta2 = fe_sqr(&beta);
        if !fe_eq(&beta2, &rhs) {
            return None; // not a quadratic residue ⇒ off curve
        }
        let want_odd = pub_[0] == 0x03;
        if fe_is_odd(&beta) != want_odd {
            beta = fe_sub(&fe_p(), &beta);
        }
        return Some((x, beta));
    }
    if plen == 65 && pub_[0] == 0x04 {
        let mut xb = [0u8; 32];
        xb.copy_from_slice(&pub_[1..33]);
        let mut yb = [0u8; 32];
        yb.copy_from_slice(&pub_[33..65]);
        let x = fe_from_be_lt_p(&xb)?;
        let y = fe_from_be_lt_p(&yb)?;
        let rhs = rhs_curve(&x);
        let y2 = fe_sqr(&y);
        if fe_eq(&y2, &rhs) {
            return Some((x, y));
        }
        return None;
    }
    None
}
pub fn secp_on_curve(pub_: &[u8]) -> bool {
    pub_decode(pub_).is_some()
}

// ── scalar arithmetic mod n ───────────────────────────────────────────────────
fn sc_n() -> [u64; 4] {
    be32_to_limbs(&SECP_N_BE)
}
fn sc_reduce(a: &mut [u64; 4]) {
    let n = sc_n();
    while limb_cmp(a, &n) >= 0 {
        let mut borrow: u128 = 0;
        for i in 0..4 {
            let x = (a[i] as u128).wrapping_sub(n[i] as u128).wrapping_sub(borrow);
            a[i] = x as u64;
            borrow = (x >> 64) & 1;
        }
    }
}
fn sc_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut t = [0u64; 8];
    for i in 0..4 {
        let mut carry: u128 = 0;
        for j in 0..4 {
            let x = a[i] as u128 * b[j] as u128 + t[i + j] as u128 + carry;
            t[i + j] = x as u64;
            carry = x >> 64;
        }
        t[i + 4] = t[i + 4].wrapping_add(carry as u64);
    }
    let n = sc_n();
    let mut rem = [0u64; 4];
    for bit in (0..512).rev() {
        let top = rem[3] >> 63;
        rem[3] = (rem[3] << 1) | (rem[2] >> 63);
        rem[2] = (rem[2] << 1) | (rem[1] >> 63);
        rem[1] = (rem[1] << 1) | (rem[0] >> 63);
        rem[0] = (rem[0] << 1) | ((t[bit >> 6] >> (bit & 63)) & 1);
        if top != 0 || limb_cmp(&rem, &n) >= 0 {
            let mut borrow: u128 = 0;
            for i in 0..4 {
                let x = (rem[i] as u128).wrapping_sub(n[i] as u128).wrapping_sub(borrow);
                rem[i] = x as u64;
                borrow = (x >> 64) & 1;
            }
        }
    }
    rem
}
fn sc_add_mod(a: &[u64; 4], b: &[u64; 4], m: &[u64; 4]) -> [u64; 4] {
    let mut s = [0u64; 4];
    let mut carry: u128 = 0;
    for i in 0..4 {
        let x = a[i] as u128 + b[i] as u128 + carry;
        s[i] = x as u64;
        carry = x >> 64;
    }
    let over = carry != 0;
    if over || limb_cmp(&s, m) >= 0 {
        let mut borrow: u128 = 0;
        for i in 0..4 {
            let x = (s[i] as u128).wrapping_sub(m[i] as u128).wrapping_sub(borrow);
            s[i] = x as u64;
            borrow = (x >> 64) & 1;
        }
    }
    s
}
fn sc_sub_mod(a: &[u64; 4], b: &[u64; 4], m: &[u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    if limb_cmp(a, b) >= 0 {
        let mut borrow: u128 = 0;
        for i in 0..4 {
            let x = (a[i] as u128).wrapping_sub(b[i] as u128).wrapping_sub(borrow);
            r[i] = x as u64;
            borrow = (x >> 64) & 1;
        }
    } else {
        let mut t = [0u64; 4];
        let mut borrow: u128 = 0;
        for i in 0..4 {
            let x = (a[i] as u128).wrapping_sub(b[i] as u128).wrapping_sub(borrow);
            t[i] = x as u64;
            borrow = (x >> 64) & 1;
        }
        let mut carry: u128 = 0;
        for i in 0..4 {
            let x = t[i] as u128 + m[i] as u128 + carry;
            r[i] = x as u64;
            carry = x >> 64;
        }
    }
    r
}
fn halve_mod(x: &mut [u64; 4], m: &[u64; 4]) {
    let odd = (x[0] & 1) == 1;
    let mut carry = 0u64;
    if odd {
        let mut c: u128 = 0;
        for i in 0..4 {
            let t = x[i] as u128 + m[i] as u128 + c;
            x[i] = t as u64;
            c = t >> 64;
        }
        carry = c as u64;
    }
    x[0] = (x[0] >> 1) | (x[1] << 63);
    x[1] = (x[1] >> 1) | (x[2] << 63);
    x[2] = (x[2] >> 1) | (x[3] << 63);
    x[3] = (x[3] >> 1) | (carry << 63);
}
fn sc_inv(a_in: &[u64; 4]) -> Option<[u64; 4]> {
    let n = sc_n();
    let mut u = *a_in;
    let mut v = n;
    let mut x1 = [1u64, 0, 0, 0];
    let mut x2 = [0u64, 0, 0, 0];
    let one = [1u64, 0, 0, 0];
    if limb_is_zero(&u) {
        return None;
    }
    while limb_cmp(&u, &one) != 0 && limb_cmp(&v, &one) != 0 {
        while (u[0] & 1) == 0 {
            u[0] = (u[0] >> 1) | (u[1] << 63);
            u[1] = (u[1] >> 1) | (u[2] << 63);
            u[2] = (u[2] >> 1) | (u[3] << 63);
            u[3] >>= 1;
            halve_mod(&mut x1, &n);
        }
        while (v[0] & 1) == 0 {
            v[0] = (v[0] >> 1) | (v[1] << 63);
            v[1] = (v[1] >> 1) | (v[2] << 63);
            v[2] = (v[2] >> 1) | (v[3] << 63);
            v[3] >>= 1;
            halve_mod(&mut x2, &n);
        }
        if limb_cmp(&u, &v) >= 0 {
            let mut borrow: u128 = 0;
            for i in 0..4 {
                let t = (u[i] as u128).wrapping_sub(v[i] as u128).wrapping_sub(borrow);
                u[i] = t as u64;
                borrow = (t >> 64) & 1;
            }
            x1 = sc_sub_mod(&x1, &x2, &n);
        } else {
            let mut borrow: u128 = 0;
            for i in 0..4 {
                let t = (v[i] as u128).wrapping_sub(u[i] as u128).wrapping_sub(borrow);
                v[i] = t as u64;
                borrow = (t >> 64) & 1;
            }
            x2 = sc_sub_mod(&x2, &x1, &n);
        }
    }
    Some(if limb_cmp(&u, &one) == 0 { x1 } else { x2 })
}

// ── ECDSA verify ──────────────────────────────────────────────────────────────
pub fn secp_ecdsa_verify(hash32: &[u8; 32], r32: &[u8; 32], s32: &[u8; 32], pub_: &[u8]) -> bool {
    let (qx, qy) = match pub_decode(pub_) {
        Some(x) => x,
        None => return false,
    };
    let n = sc_n();
    let r = be32_to_limbs(r32);
    let s = be32_to_limbs(s32);
    let mut z = be32_to_limbs(hash32);
    if limb_is_zero(&r) || limb_cmp(&r, &n) >= 0 {
        return false;
    }
    if limb_is_zero(&s) || limb_cmp(&s, &n) >= 0 {
        return false;
    }
    sc_reduce(&mut z);
    let w = match sc_inv(&s) {
        Some(x) => x,
        None => return false,
    };
    let u1 = sc_mul(&z, &w);
    let u2 = sc_mul(&r, &w);
    let u1b = limbs_to_be32(&u1);
    let u2b = limbs_to_be32(&u2);
    let g = secp_g();
    let q = jac_from_affine(&qx, &qy);
    let a = jac_mul(&g, &u1b);
    let b = jac_mul(&q, &u2b);
    let rj = jac_add(&a, &b);
    let (rx, _ry) = match jac_affine(&rj) {
        Some(p) => p,
        None => return false,
    };
    let mut xr = rx.v;
    sc_reduce(&mut xr);
    limb_cmp(&xr, &r) == 0
}

// ── HMAC-SHA256 ───────────────────────────────────────────────────────────────
fn sha256_buf(d: &[u8]) -> [u8; 32] {
    let mut c = Sha256::new();
    c.update(d);
    c.finalize()
}
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let h = sha256_buf(key);
        k[..32].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ki = [0u8; 64];
    let mut ko = [0u8; 64];
    for i in 0..64 {
        ki[i] = k[i] ^ 0x36;
        ko[i] = k[i] ^ 0x5c;
    }
    let mut c = Sha256::new();
    c.update(&ki);
    c.update(msg);
    let inner = c.finalize();
    let mut c2 = Sha256::new();
    c2.update(&ko);
    c2.update(&inner);
    c2.finalize()
}

// ── RFC-6979 nonce + ECDSA sign ───────────────────────────────────────────────
fn rfc6979_k(priv32: &[u8; 32], hash32: &[u8; 32]) -> [u8; 32] {
    let n = sc_n();
    let mut hz = be32_to_limbs(hash32); // bits2octets(h1) = (h1 mod n) BE
    sc_reduce(&mut hz);
    let h1o = limbs_to_be32(&hz);
    let mut v = [0x01u8; 32];
    let mut k = [0x00u8; 32];
    // K = HMAC_K(V ‖ 0x00 ‖ x ‖ h1o)
    let mut buf = Vec::with_capacity(32 + 1 + 32 + 32);
    buf.extend_from_slice(&v);
    buf.push(0x00);
    buf.extend_from_slice(priv32);
    buf.extend_from_slice(&h1o);
    k = hmac_sha256(&k, &buf);
    v = hmac_sha256(&k, &v); // V = HMAC_K(V)
    buf.clear();
    buf.extend_from_slice(&v);
    buf.push(0x01);
    buf.extend_from_slice(priv32);
    buf.extend_from_slice(&h1o);
    k = hmac_sha256(&k, &buf);
    v = hmac_sha256(&k, &v);
    loop {
        v = hmac_sha256(&k, &v); // T = V (qlen == 256 ⇒ one block)
        let kz = be32_to_limbs(&v);
        if !limb_is_zero(&kz) && limb_cmp(&kz, &n) < 0 {
            return v;
        }
        let mut b2 = [0u8; 33];
        b2[..32].copy_from_slice(&v);
        b2[32] = 0x00;
        k = hmac_sha256(&k, &b2);
        v = hmac_sha256(&k, &v);
    }
}
pub fn secp_ecdsa_sign(priv32: &[u8; 32], hash32: &[u8; 32]) -> Option<([u8; 32], [u8; 32])> {
    let n = sc_n();
    let d = be32_to_limbs(priv32);
    if limb_is_zero(&d) || limb_cmp(&d, &n) >= 0 {
        return None;
    }
    let mut z = be32_to_limbs(hash32);
    sc_reduce(&mut z);
    let mut feed = *hash32;
    for _ in 0..64 {
        let kb = rfc6979_k(priv32, &feed);
        let g = secp_g();
        let rpt = jac_mul(&g, &kb);
        let (rx, _) = match jac_affine(&rpt) {
            Some(p) => p,
            None => {
                feed = sha256_buf(&kb);
                continue;
            }
        };
        let mut r = rx.v;
        sc_reduce(&mut r);
        if limb_is_zero(&r) {
            feed = sha256_buf(&kb);
            continue;
        }
        let kk = be32_to_limbs(&kb);
        let kinv = match sc_inv(&kk) {
            Some(x) => x,
            None => {
                feed = sha256_buf(&kb);
                continue;
            }
        };
        let rd = sc_mul(&r, &d);
        let zrd = sc_add_mod(&z, &rd, &n);
        let mut s = sc_mul(&kinv, &zrd);
        if limb_is_zero(&s) {
            feed = sha256_buf(&kb);
            continue;
        }
        let nh = be32_to_limbs(&SECP_N_HALF_BE);
        if limb_cmp(&s, &nh) > 0 {
            // low-S: s = n - s
            let mut ns = [0u64; 4];
            let mut borrow: u128 = 0;
            for i in 0..4 {
                let x = (n[i] as u128).wrapping_sub(s[i] as u128).wrapping_sub(borrow);
                ns[i] = x as u64;
                borrow = (x >> 64) & 1;
            }
            s = ns;
        }
        return Some((limbs_to_be32(&r), limbs_to_be32(&s)));
    }
    None
}
pub fn secp_pubkey(priv32: &[u8; 32]) -> Option<[u8; 33]> {
    let n = sc_n();
    let d = be32_to_limbs(priv32);
    if limb_is_zero(&d) || limb_cmp(&d, &n) >= 0 {
        return None;
    }
    let g = secp_g();
    let p = jac_mul(&g, priv32);
    let (x, y) = jac_affine(&p)?;
    let mut out = [0u8; 33];
    out[0] = if fe_is_odd(&y) { 0x03 } else { 0x02 };
    out[1..].copy_from_slice(&limbs_to_be32(&x.v));
    Some(out)
}

// ── ECMH (Elliptic Curve Multiset Hash) ───────────────────────────────────────
// An accumulator is a 33-byte compressed point (0x02/0x03 ‖ X-be); the all-zero
// sentinel (prefix 0x00) is the identity ∞.  Mirrors secp256k1.c's ECMH block.
const ECMH_H2C_TAG: [u8; 8] = [b'E', b'C', b'M', b'H', b'h', b'2', b'c', b'1'];

pub fn secp_ecmh_identity() -> [u8; 33] {
    [0u8; 33]
}

fn ecmh_ser(p: &Jac) -> [u8; 33] {
    // point → 33 bytes (∞ → zeros)
    match jac_affine(p) {
        None => [0u8; 33],
        Some((x, y)) => {
            let mut out = [0u8; 33];
            out[0] = if fe_is_odd(&y) { 0x03 } else { 0x02 };
            out[1..].copy_from_slice(&limbs_to_be32(&x.v));
            out
        }
    }
}
fn ecmh_load(in33: &[u8; 33]) -> Jac {
    // 33 bytes → point
    if in33[0] == 0 {
        return jac_set_inf();
    }
    let (x, y) = pub_decode(in33).unwrap();
    jac_from_affine(&x, &y)
}

// try-and-increment hash-to-curve; returns (ctr, compressed even-Y point).
pub fn secp_ecmh_hash(pre: &[u8]) -> (i32, [u8; 33]) {
    let mut ctr: i32 = 0;
    loop {
        let mut c = Sha256::new();
        c.update(&ECMH_H2C_TAG);
        if !pre.is_empty() {
            c.update(pre);
        }
        let cb = [ctr as u8, (ctr >> 8) as u8, (ctr >> 16) as u8, (ctr >> 24) as u8];
        c.update(&cb);
        let h = c.finalize();
        let mut x = Fe { v: be32_to_limbs(&h) };
        fe_cond_sub_p(&mut x); // x = SHA256(...) mod p
        let rhs = rhs_curve(&x);
        let beta = fe_sqrt(&rhs);
        let b2 = fe_sqr(&beta);
        if !fe_eq(&b2, &rhs) {
            ctr += 1;
            continue; // x³+7 not a QR ⇒ bump ctr
        }
        let mut pt = [0u8; 33];
        pt[0] = 0x02; // canonical even-Y
        pt[1..].copy_from_slice(&limbs_to_be32(&x.v));
        return (ctr, pt);
    }
}

pub fn secp_ecmh_negate(pt33: &mut [u8; 33]) {
    if pt33[0] != 0 {
        pt33[0] ^= 1;
    }
}

pub fn secp_ecmh_add(acc33: &mut [u8; 33], pt33: &[u8; 33]) {
    let a = ecmh_load(acc33);
    let p = ecmh_load(pt33);
    let r = jac_add(&a, &p);
    *acc33 = ecmh_ser(&r);
}

// ── self-check (returns failure count; 0 = OK) ───────────────────────────────
pub fn secp_selftest() -> i32 {
    let mut fail = 0;
    // constants: N_HALF = N>>1.
    {
        let n = sc_n();
        let nh = be32_to_limbs(&SECP_N_HALF_BE);
        let mut h = n;
        h[0] = (h[0] >> 1) | (h[1] << 63);
        h[1] = (h[1] >> 1) | (h[2] << 63);
        h[2] = (h[2] >> 1) | (h[3] << 63);
        h[3] >>= 1;
        if limb_cmp(&h, &nh) != 0 {
            fail += 1;
        }
    }
    // G on curve via the uncompressed encoding.
    {
        let mut g = [0u8; 65];
        g[0] = 0x04;
        g[1..33].copy_from_slice(&SECP_GX_BE);
        g[33..].copy_from_slice(&SECP_GY_BE);
        if !secp_on_curve(&g) {
            fail += 1;
        }
    }
    // 2G known-answer.
    {
        let mut two = [0u8; 32];
        two[31] = 2;
        const G2X: [u8; 32] = [
            0xC6, 0x04, 0x7F, 0x94, 0x41, 0xED, 0x7D, 0x6D, 0x30, 0x45, 0x40, 0x6E, 0x95, 0xC0, 0x7C,
            0xD8, 0x5C, 0x77, 0x8E, 0x4B, 0x8C, 0xEF, 0x3C, 0xA7, 0xAB, 0xAC, 0x09, 0xB9, 0x5C, 0x70,
            0x9E, 0xE5,
        ];
        const G2Y: [u8; 32] = [
            0x1A, 0xE1, 0x68, 0xFE, 0xA6, 0x3D, 0xC3, 0x39, 0xA3, 0xC5, 0x84, 0x19, 0x46, 0x6C, 0xEA,
            0xEE, 0xF7, 0xF6, 0x32, 0x65, 0x32, 0x66, 0xD0, 0xE1, 0x23, 0x64, 0x31, 0xA9, 0x50, 0xCF,
            0xE5, 0x2A,
        ];
        let g = secp_g();
        let p = jac_mul(&g, &two);
        match jac_affine(&p) {
            None => fail += 1,
            Some((x, y)) => {
                if limbs_to_be32(&x.v) != G2X || limbs_to_be32(&y.v) != G2Y {
                    fail += 1;
                }
            }
        }
    }
    // n·G == ∞.
    {
        let g = secp_g();
        let p = jac_mul(&g, &SECP_N_BE);
        if jac_affine(&p).is_some() {
            fail += 1;
        }
    }
    // decompress round-trip: compress G (even), decode, compare.
    {
        let mut gc = [0u8; 33];
        gc[0] = 0x02;
        gc[1..].copy_from_slice(&SECP_GX_BE);
        match pub_decode(&gc) {
            None => fail += 1,
            Some((_, y)) => {
                if limbs_to_be32(&y.v) != SECP_GY_BE {
                    fail += 1;
                }
            }
        }
    }
    // sign / verify round-trip + tamper check over a few deterministic keys.
    for t in 1..=4u8 {
        let mut priv_ = [0u8; 32];
        priv_[31] = t * 7 + 1;
        let pubk = match secp_pubkey(&priv_) {
            Some(p) => p,
            None => {
                fail += 1;
                continue;
            }
        };
        let mut msg = [0u8; 32];
        for i in 0..32 {
            msg[i] = (i as u8).wrapping_mul(13).wrapping_add(t);
        }
        let mh = sha256_buf(&msg);
        let (r, s) = match secp_ecdsa_sign(&priv_, &mh) {
            Some(rs) => rs,
            None => {
                fail += 1;
                continue;
            }
        };
        if !secp_ecdsa_verify(&mh, &r, &s, &pubk) {
            fail += 1;
        }
        let mut mh2 = mh;
        mh2[0] ^= 0x01;
        if secp_ecdsa_verify(&mh2, &r, &s, &pubk) {
            fail += 1;
        }
    }
    // ECMH algebra: commutativity, identity, inverse, add-then-remove round-trip.
    fail += secp_selftest_ecmh();
    fail
}

// ECMH algebra self-check (returns failure count; 0 = OK). Mirrors C secp_ecmh_selftest.
pub fn secp_selftest_ecmh() -> i32 {
    let mut fail = 0;
    let id = secp_ecmh_identity();
    let (_, pa) = secp_ecmh_hash(b"alpha");
    let (_, pb) = secp_ecmh_hash(b"beta");
    let mut acc1 = secp_ecmh_identity();
    secp_ecmh_add(&mut acc1, &pa);
    secp_ecmh_add(&mut acc1, &pb);
    let mut acc2 = secp_ecmh_identity();
    secp_ecmh_add(&mut acc2, &pb);
    secp_ecmh_add(&mut acc2, &pa);
    if acc1 != acc2 {
        fail += 1; // commutativity
    }
    let mut acc1 = secp_ecmh_identity();
    secp_ecmh_add(&mut acc1, &pa);
    if acc1 != pa {
        fail += 1; // identity: ∞ + P == P
    }
    let mut npa = pa;
    secp_ecmh_negate(&mut npa);
    let mut acc1 = secp_ecmh_identity();
    secp_ecmh_add(&mut acc1, &pa);
    secp_ecmh_add(&mut acc1, &npa);
    if acc1 != id {
        fail += 1; // inverse: P + (−P) == ∞
    }
    let mut acc1 = secp_ecmh_identity();
    secp_ecmh_add(&mut acc1, &pa);
    let mut acc2 = acc1;
    secp_ecmh_add(&mut acc2, &pb);
    let mut npb = pb;
    secp_ecmh_negate(&mut npb);
    secp_ecmh_add(&mut acc2, &npb);
    if acc1 != acc2 {
        fail += 1; // add-then-remove round-trip
    }
    fail
}
