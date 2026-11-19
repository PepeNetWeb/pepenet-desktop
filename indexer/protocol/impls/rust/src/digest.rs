//! Canonical SHA-256 state digest (SPEC-conformance.md §4). Byte-exact layout.
//! Multi-byte ints little-endian; signed two's-complement LE.
//! Magic "SMv1"; tables: names + commits + muts only (names-only SM).

use crate::fold::{St, State};
use crate::secp256k1::{secp_ecmh_add, secp_ecmh_hash, secp_ecmh_identity};
use crate::sha256::sha256;

fn push_i64(buf: &mut Vec<u8>, v: i64) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn push_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn push_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

pub fn state_digest(st: &State) -> [u8; 32] {
    let buf = serialize(st);
    sha256(&buf)
}

// ── ECMH state digest (§13.2) — the incremental twin of state_digest ───────────
// Three per-table ECMH sub-accumulators over the SAME per-row encoding state_digest
// uses (without count prefixes / "SMv1" framing), combined into one SHA-256.
// Domain tags separate the tables. Mirrors impls/c/src/ecmh.c sm_state_ecmh.
const TAG_NAME: u8 = 0x01;
const TAG_COMMIT: u8 = 0x02;
const TAG_MUT: u8 = 0x04;
const ECMH_REC_TAG: &[u8; 6] = b"ECMHv1";

// acc ← acc + H2C("ECMHv1" ‖ tag ‖ row_bytes).
fn ecmh_fold_row(acc: &mut [u8; 33], tag: u8, row: &[u8]) {
    let mut pre = Vec::with_capacity(7 + row.len());
    pre.extend_from_slice(ECMH_REC_TAG);
    pre.push(tag);
    pre.extend_from_slice(row);
    let (_ctr, pt) = secp_ecmh_hash(&pre);
    secp_ecmh_add(acc, &pt);
}

pub fn state_ecmh(st: &State) -> [u8; 32] {
    let mut an = secp_ecmh_identity();
    let mut ac = secp_ecmh_identity();
    let mut am = secp_ecmh_identity();

    // names — per-row fields identical to serialize() (no count prefix)
    for (name, r) in st.names.iter() {
        let mut b = Vec::new();
        b.push(name.len() as u8);
        b.extend_from_slice(name);
        b.extend_from_slice(&r.owner);
        b.push(r.st as u8);
        push_i64(&mut b, r.lease_expiry);
        b.extend_from_slice(&r.seller);
        b.push(r.seller_type.as_u8());
        push_u64(&mut b, r.price);
        push_i64(&mut b, r.offer_expiry);
        b.extend_from_slice(&r.buyer);
        push_u64(&mut b, r.burn_leg);
        push_u64(&mut b, r.pay_leg);
        push_i64(&mut b, r.reserve_expiry);
        ecmh_fold_row(&mut an, TAG_NAME, &b);
    }
    // commits — order-independent sum, so no sort needed
    for c in st.commits.iter() {
        let mut b = Vec::new();
        b.extend_from_slice(&c.commitment);
        push_i64(&mut b, c.commit_height);
        push_u32(&mut b, c.tx_index);
        push_i64(&mut b, c.commit_time);
        ecmh_fold_row(&mut ac, TAG_COMMIT, &b);
    }
    // muts
    for (owner, height) in st.muts.iter() {
        let mut b = Vec::new();
        b.extend_from_slice(owner);
        push_i64(&mut b, *height);
        ecmh_fold_row(&mut am, TAG_MUT, &b);
    }

    // combined = SHA256("ECMHtop1" ‖ the three sub-accumulators).
    let mut buf = Vec::with_capacity(8 + 33 * 3);
    buf.extend_from_slice(b"ECMHtop1");
    buf.extend_from_slice(&an);
    buf.extend_from_slice(&ac);
    buf.extend_from_slice(&am);
    sha256(&buf)
}

pub fn serialize(st: &State) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"SMv1");

    // names — BTreeMap already ascending by raw name bytes
    push_u32(&mut buf, st.names.len() as u32);
    for (name, r) in st.names.iter() {
        buf.push(name.len() as u8);
        buf.extend_from_slice(name);
        buf.extend_from_slice(&r.owner);
        buf.push(r.st as u8);
        push_i64(&mut buf, r.lease_expiry);
        buf.extend_from_slice(&r.seller);
        buf.push(r.seller_type.as_u8());
        push_u64(&mut buf, r.price);
        push_i64(&mut buf, r.offer_expiry);
        buf.extend_from_slice(&r.buyer);
        push_u64(&mut buf, r.burn_leg);
        push_u64(&mut buf, r.pay_leg);
        push_i64(&mut buf, r.reserve_expiry);
    }

    // commits — sorted by (commitment[32], commit_height, tx_index) [total order]
    let mut commits: Vec<&crate::fold::CommitRow> = st.commits.iter().collect();
    commits.sort_by(|a, b| {
        a.commitment
            .cmp(&b.commitment)
            .then(a.commit_height.cmp(&b.commit_height))
            .then(a.tx_index.cmp(&b.tx_index))
    });
    push_u32(&mut buf, commits.len() as u32);
    for c in commits {
        buf.extend_from_slice(&c.commitment);
        push_i64(&mut buf, c.commit_height);
        push_u32(&mut buf, c.tx_index);
        push_i64(&mut buf, c.commit_time);
    }

    // muts — sorted by owner bytes (BTreeMap order)
    push_u32(&mut buf, st.muts.len() as u32);
    for (owner, height) in st.muts.iter() {
        buf.extend_from_slice(owner);
        push_i64(&mut buf, *height);
    }

    buf
}

pub fn hex32(d: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in d {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Helper for selftest: count rows in a given state.
pub fn state_n_owned(st: &State) -> usize {
    st.names.values().filter(|r| r.st == St::Owned).count()
}
