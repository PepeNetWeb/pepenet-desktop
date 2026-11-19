//! §4 Stateless Identity & Attribution byte-logic (conformance §13).
//! Real byte-logic (DER/low-S, pubkey canon, templates, minimal-push, legacy sighash +
//! FindAndDelete, hash160). The elliptic curve is the ONLY injected part (on_curve / verify).

use crate::ripemd160::hash160;
use crate::sha256::{sha256, sha256d};

// secp256k1 constants (big-endian, 32 bytes).
const SECP_P: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
];
const SECP_N_HALF: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

// ---- curve oracle (injected pseudo-funcs by default; real secp256k1 when toggled) ----
// The §4 byte-logic (attrib / attrib-scenario / selftest) keeps the injected oracle so its
// digests stay byte-identical cross-language. The §4 Strategy-B end-to-end vectors flip
// G_REAL_CURVE on so attribute() routes through real on_curve / ecdsa_verify (mirrors the
// C impl's g_real_curve global).
use std::cell::Cell;
thread_local!(static G_REAL_CURVE: Cell<bool> = Cell::new(false));

pub fn set_real_curve(on: bool) {
    G_REAL_CURVE.with(|f| f.set(on));
}
fn real_curve() -> bool {
    G_REAL_CURVE.with(|f| f.get())
}

fn inj_on_curve(pubkey: &[u8]) -> bool {
    let mut m = Vec::with_capacity(1 + pubkey.len());
    m.push(0x4F);
    m.extend_from_slice(pubkey);
    sha256(&m)[0] != 0x00
}
fn inj_verify(hash32: &[u8; 32], r32: &[u8; 32], s32: &[u8; 32], pubkey: &[u8]) -> bool {
    let mut m = Vec::with_capacity(1 + 32 + 32 + 32 + pubkey.len());
    m.push(0x56);
    m.extend_from_slice(hash32);
    m.extend_from_slice(r32);
    m.extend_from_slice(s32);
    m.extend_from_slice(pubkey);
    sha256(&m)[0] >= 0x20
}
pub fn on_curve(pubkey: &[u8]) -> bool {
    if real_curve() {
        crate::secp256k1::secp_on_curve(pubkey)
    } else {
        inj_on_curve(pubkey)
    }
}
pub fn verify(hash32: &[u8; 32], r32: &[u8; 32], s32: &[u8; 32], pubkey: &[u8]) -> bool {
    if real_curve() {
        crate::secp256k1::secp_ecdsa_verify(hash32, r32, s32, pubkey)
    } else {
        inj_verify(hash32, r32, s32, pubkey)
    }
}

// ---- raw tx parsing (legacy serialization) ----
pub struct TxIn {
    pub prevout: [u8; 36],
    pub scriptsig: Vec<u8>,
    pub sequence: u32,
}
pub struct TxOut {
    pub value: u64,
    pub spk: Vec<u8>,
}
pub struct ParsedTx {
    pub version: u32,
    pub vin: Vec<TxIn>,
    pub vout: Vec<TxOut>,
    pub locktime: u32,
}

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Reader<'a> {
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.p)?;
        self.p += 1;
        Some(v)
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.p + n > self.b.len() {
            return None;
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Some(s)
    }
    fn u32le(&mut self) -> Option<u32> {
        let s = self.take(4)?;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64le(&mut self) -> Option<u64> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Some(u64::from_le_bytes(a))
    }
    fn varint(&mut self) -> Option<u64> {
        let f = self.u8()?;
        Some(match f {
            0xfd => {
                let s = self.take(2)?;
                u16::from_le_bytes([s[0], s[1]]) as u64
            }
            0xfe => self.u32le()? as u64,
            0xff => self.u64le()?,
            x => x as u64,
        })
    }
}

pub fn parse_tx(raw: &[u8]) -> Option<ParsedTx> {
    let mut r = Reader { b: raw, p: 0 };
    let version = r.u32le()?;
    let nin = r.varint()?;
    if nin == 0 || nin > 100_000 {
        return None;
    }
    let mut vin = Vec::with_capacity(nin as usize);
    for _ in 0..nin {
        let mut prevout = [0u8; 36];
        prevout.copy_from_slice(r.take(36)?);
        let sl = r.varint()? as usize;
        let scriptsig = r.take(sl)?.to_vec();
        let sequence = r.u32le()?;
        vin.push(TxIn { prevout, scriptsig, sequence });
    }
    let nout = r.varint()?;
    if nout > 100_000 {
        return None;
    }
    let mut vout = Vec::with_capacity(nout as usize);
    for _ in 0..nout {
        let value = r.u64le()?;
        let sl = r.varint()? as usize;
        let spk = r.take(sl)?.to_vec();
        vout.push(TxOut { value, spk });
    }
    let locktime = r.u32le()?;
    if r.p != raw.len() {
        return None; // trailing bytes → malformed
    }
    Some(ParsedTx { version, vin, vout, locktime })
}

// ---- minimal-push iterator ----
/// Parse a script as a sequence of data pushes (OP_0 → empty). Any non-push opcode,
/// non-minimal push, or truncation → None (classify-drop).
fn parse_pushes(script: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let n = script.len();
    while i < n {
        let op = script[i];
        i += 1;
        match op {
            0x00 => out.push(Vec::new()), // OP_0 pushes empty
            0x01..=0x4b => {
                let len = op as usize;
                if i + len > n {
                    return None;
                }
                out.push(script[i..i + len].to_vec());
                i += len;
            }
            0x4c => {
                // PUSHDATA1: len must be 76..=255 (minimal)
                if i >= n {
                    return None;
                }
                let len = script[i] as usize;
                i += 1;
                if len < 76 {
                    return None; // non-minimal
                }
                if i + len > n {
                    return None;
                }
                out.push(script[i..i + len].to_vec());
                i += len;
            }
            0x4d => {
                // PUSHDATA2: len must be 256..=65535 (minimal); our template caps ≤520
                if i + 2 > n {
                    return None;
                }
                let len = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
                i += 2;
                if len < 256 {
                    return None; // non-minimal
                }
                if i + len > n {
                    return None;
                }
                out.push(script[i..i + len].to_vec());
                i += len;
            }
            _ => return None, // PUSHDATA4, OP_1.., or any non-push opcode
        }
    }
    Some(out)
}

// ---- DER strict + low-S ----
/// Validate sig = DER ‖ hashtype. hashtype MUST be 0x01. Returns (r32, s32) on success.
fn der_low_s(sig: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if sig.len() < 9 || sig.len() > 73 {
        return None;
    }
    let hashtype = *sig.last().unwrap();
    if hashtype != 0x01 {
        return None; // Rule 3: SIGHASH_ALL only
    }
    let der = &sig[..sig.len() - 1];
    // BIP66 structure
    if der[0] != 0x30 {
        return None;
    }
    if der[1] as usize != der.len() - 2 {
        return None;
    }
    if der[2] != 0x02 {
        return None;
    }
    let rlen = der[3] as usize;
    if 4 + rlen + 2 > der.len() {
        return None;
    }
    let r = &der[4..4 + rlen];
    if der[4 + rlen] != 0x02 {
        return None;
    }
    let slen = der[4 + rlen + 1] as usize;
    if 4 + rlen + 2 + slen != der.len() {
        return None; // trailing or mismatch
    }
    let s = &der[4 + rlen + 2..];
    // no zero-length, no negative, no excess padding
    if rlen == 0 || slen == 0 {
        return None;
    }
    if r[0] & 0x80 != 0 {
        return None; // negative
    }
    if r[0] == 0x00 && (rlen == 1 || r[1] & 0x80 == 0) {
        return None; // excess padding
    }
    if s[0] & 0x80 != 0 {
        return None;
    }
    if s[0] == 0x00 && (slen == 1 || s[1] & 0x80 == 0) {
        return None;
    }
    // low-S: S ≤ N/2
    let s32 = be_to_32(s)?;
    if cmp_be(&s32, &SECP_N_HALF) == std::cmp::Ordering::Greater {
        return None;
    }
    let r32 = be_to_32(r)?;
    Some((r32, s32))
}

fn be_to_32(v: &[u8]) -> Option<[u8; 32]> {
    // strip a single leading 0x00 (DER positive padding) then left-pad to 32; reject >32 magnitude
    let mut start = 0;
    if v.len() > 1 && v[0] == 0x00 {
        start = 1;
    }
    let mag = &v[start..];
    if mag.len() > 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out[32 - mag.len()..].copy_from_slice(mag);
    Some(out)
}

fn cmp_be(a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
    a.cmp(b)
}

/// Pubkey canonical encoding (struct + coords<p). On-curve is the injected part, NOT here.
fn pubkey_canonical(pk: &[u8]) -> bool {
    match pk.len() {
        33 => {
            if pk[0] != 0x02 && pk[0] != 0x03 {
                return false;
            }
            let mut x = [0u8; 32];
            x.copy_from_slice(&pk[1..33]);
            cmp_be(&x, &SECP_P) == std::cmp::Ordering::Less
        }
        65 => {
            if pk[0] != 0x04 {
                return false; // reject hybrid 0x06/0x07
            }
            let mut x = [0u8; 32];
            let mut y = [0u8; 32];
            x.copy_from_slice(&pk[1..33]);
            y.copy_from_slice(&pk[33..65]);
            cmp_be(&x, &SECP_P) == std::cmp::Ordering::Less
                && cmp_be(&y, &SECP_P) == std::cmp::Ordering::Less
        }
        _ => false,
    }
}

// ---- FindAndDelete (Bitcoin Core CScript semantics) ----
pub fn find_and_delete(script: &[u8], pat: &[u8]) -> Vec<u8> {
    if pat.is_empty() {
        return script.to_vec();
    }
    let mut result = Vec::new();
    let mut pc = 0usize;
    let mut pc2 = 0usize;
    let mut found = 0usize;
    loop {
        result.extend_from_slice(&script[pc2..pc]);
        while pc + pat.len() <= script.len() && &script[pc..pc + pat.len()] == pat {
            pc += pat.len();
            found += 1;
        }
        pc2 = pc;
        match get_op(script, pc) {
            Some(next) => pc = next,
            None => break,
        }
    }
    if found > 0 {
        result.extend_from_slice(&script[pc2..]);
        result
    } else {
        script.to_vec()
    }
}

/// Advance past one opcode at pc; None at end or on truncated push.
fn get_op(script: &[u8], pc: usize) -> Option<usize> {
    if pc >= script.len() {
        return None;
    }
    let op = script[pc];
    let next = match op {
        0x00..=0x4b => pc + 1 + op as usize,
        0x4c => {
            let l = *script.get(pc + 1)? as usize;
            pc + 2 + l
        }
        0x4d => {
            let l = u16::from_le_bytes([*script.get(pc + 1)?, *script.get(pc + 2)?]) as usize;
            pc + 3 + l
        }
        0x4e => {
            let s = script.get(pc + 1..pc + 5)?;
            let l = u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize;
            pc + 5 + l
        }
        _ => pc + 1,
    };
    if next > script.len() {
        return None;
    }
    Some(next)
}

/// Canonical push of `data` (minimal). Used to build a signature push for FindAndDelete.
fn push_bytes(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
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
    out
}

// ---- legacy sighash ----
pub(crate) fn legacy_sighash(tx: &ParsedTx, idx: usize, script_code: &[u8]) -> [u8; 32] {
    let mut s = Vec::new();
    s.extend_from_slice(&tx.version.to_le_bytes());
    write_varint(&mut s, tx.vin.len() as u64);
    for (i, inp) in tx.vin.iter().enumerate() {
        s.extend_from_slice(&inp.prevout);
        let sc: &[u8] = if i == idx { script_code } else { &[] };
        write_varint(&mut s, sc.len() as u64);
        s.extend_from_slice(sc);
        s.extend_from_slice(&inp.sequence.to_le_bytes());
    }
    write_varint(&mut s, tx.vout.len() as u64);
    for o in &tx.vout {
        s.extend_from_slice(&o.value.to_le_bytes());
        write_varint(&mut s, o.spk.len() as u64);
        s.extend_from_slice(&o.spk);
    }
    s.extend_from_slice(&tx.locktime.to_le_bytes());
    // hashtype as 4-byte LE int32 (0x01 0x00 0x00 0x00) — consensus-critical width
    s.extend_from_slice(&1u32.to_le_bytes());
    sha256d(&s)
}

fn write_varint(buf: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

fn p2pkh_script_code(identity: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(25);
    s.push(0x76); // OP_DUP
    s.push(0xa9); // OP_HASH160
    s.push(0x14); // push 20
    s.extend_from_slice(identity);
    s.push(0x88); // OP_EQUALVERIFY
    s.push(0xac); // OP_CHECKSIG
    s
}

// ---- attribute ----
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Attribution {
    pub status: u8, // 0 classify-drop, 1 on-curve-drop, 2 verify-drop, 3 found
    pub sighash: [u8; 32],
    pub identity: [u8; 20],
}

const ZERO_ATTR: Attribution = Attribution { status: 0, sighash: [0u8; 32], identity: [0u8; 20] };

pub fn attribute(tx: &ParsedTx, k: usize) -> Attribution {
    let inp = match tx.vin.get(k) {
        Some(x) => x,
        None => return ZERO_ATTR,
    };
    let pushes = match parse_pushes(&inp.scriptsig) {
        Some(p) => p,
        None => return ZERO_ATTR,
    };

    // P2PKH: exactly [sig][pubkey], both non-empty
    if pushes.len() == 2 && !pushes[0].is_empty() && !pushes[1].is_empty() {
        let sig = &pushes[0];
        let pk = &pushes[1];
        let (r32, s32) = match der_low_s(sig) {
            Some(x) => x,
            None => return ZERO_ATTR,
        };
        if !pubkey_canonical(pk) {
            return ZERO_ATTR;
        }
        // classification succeeded → identity + sighash formed now (before any curve gate),
        // so even an on-curve-drop carries the real identity+sighash (§13).
        let identity = hash160(pk);
        let sc = p2pkh_script_code(&identity);
        let scd = find_and_delete(&sc, &push_bytes(sig)); // inert for P2PKH (hash only)
        let sighash = legacy_sighash(tx, k, &scd);
        // on_curve gates the P2PKH key too (§4 Rule 4 "Non-canonical → drop"): a well-encoded
        // but off-curve pubkey is status 1, exactly like the multisig keys below — NOT routed
        // through verify(). (Matches impls/c attrib.c; the earlier redeemScript-only reading was
        // the A7 consensus-fork divergence the clean-room audit caught.)
        if !on_curve(pk) {
            return Attribution { status: 1, sighash, identity };
        }
        let st = if verify(&sighash, &r32, &s32, pk) { 3 } else { 2 };
        return Attribution { status: st, sighash, identity };
    }

    // P2SH multisig: [OP_0][sig]×m[redeemScript]
    if pushes.len() >= 3 && pushes[0].is_empty() {
        let redeem = pushes.last().unwrap();
        let sigs = &pushes[1..pushes.len() - 1];
        // parse template: OP_m, n×(0x21 + 33B key), OP_n, OP_CHECKMULTISIG
        let tmpl = match parse_multisig_template(redeem) {
            Some(t) => t,
            None => return ZERO_ATTR,
        };
        let (m, keys) = tmpl;
        if sigs.len() != m as usize {
            return ZERO_ATTR; // sig count ≠ m
        }
        // DER+low-S on every sig (structural, before curve)
        let mut parsed_sigs = Vec::with_capacity(sigs.len());
        for sg in sigs {
            match der_low_s(sg) {
                Some(rs) => parsed_sigs.push((sg.clone(), rs.0, rs.1)),
                None => return ZERO_ATTR,
            }
        }
        // classification succeeded → identity + sighash
        let identity = hash160(redeem);
        let mut scd = redeem.clone();
        for (sg, _, _) in &parsed_sigs {
            scd = find_and_delete(&scd, &push_bytes(sg)); // inert on rigid template
        }
        let sighash = legacy_sighash(tx, k, &scd);
        // on_curve on ALL n keys up front
        if keys.iter().any(|kk| !on_curve(kk)) {
            return Attribution { status: 1, sighash, identity };
        }
        // in-order signature scan
        let mut key_cur = 0usize;
        let mut matched = 0usize;
        for (_, r32, s32) in &parsed_sigs {
            while key_cur < keys.len() {
                if verify(&sighash, r32, s32, &keys[key_cur]) {
                    key_cur += 1;
                    matched += 1;
                    break;
                } else {
                    key_cur += 1;
                }
            }
        }
        let st = if matched == m as usize { 3 } else { 2 };
        return Attribution { status: st, sighash, identity };
    }

    ZERO_ATTR
}

/// Parse the multisig redeemScript template. Returns (m, keys[n]) or None.
fn parse_multisig_template(rs: &[u8]) -> Option<(u8, Vec<Vec<u8>>)> {
    if rs.len() < 3 {
        return None;
    }
    let m_op = rs[0];
    if !(0x51..=0x60).contains(&m_op) {
        return None;
    }
    let m = m_op - 0x50;
    let mut i = 1usize;
    let mut keys = Vec::new();
    while i < rs.len() && rs[i] == 0x21 {
        // 33-byte compressed key push
        if i + 1 + 33 > rs.len() {
            return None;
        }
        let key = &rs[i + 1..i + 1 + 33];
        if key[0] != 0x02 && key[0] != 0x03 {
            return None;
        }
        let mut x = [0u8; 32];
        x.copy_from_slice(&key[1..33]);
        if cmp_be(&x, &SECP_P) != std::cmp::Ordering::Less {
            return None; // X out of range
        }
        keys.push(key.to_vec());
        i += 34;
    }
    // OP_n
    if i >= rs.len() {
        return None;
    }
    let n_op = rs[i];
    if !(0x51..=0x60).contains(&n_op) {
        return None;
    }
    let n = n_op - 0x50;
    i += 1;
    if keys.len() != n as usize {
        return None;
    }
    if !(1..=15).contains(&n) || !(1..=n).contains(&m) {
        return None; // 1 ≤ m ≤ n ≤ 15
    }
    // OP_CHECKMULTISIG
    if i >= rs.len() || rs[i] != 0xae {
        return None;
    }
    i += 1;
    if i != rs.len() {
        return None; // trailing bytes
    }
    Some((m, keys))
}
