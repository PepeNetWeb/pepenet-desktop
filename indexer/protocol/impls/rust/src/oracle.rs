//! Fee oracle (§3.4) and MTP (§5) — pinned integer-deterministic math.

use crate::types::*;

/// Per-block fee_per_byte = ⌊max(0, coinbase − subsidy)/bytes⌋ with the subtraction SIGNED.
/// Computed in i128 to avoid any unsigned wrap on a miner under-claim.
pub fn fee_per_byte(coinbase_total: u64, subsidy: u64, block_bytes: u64) -> u64 {
    // block_bytes is always ≥ 1 (every block has a coinbase tx); if a reading is 0, the
    // divisor is pinned to 1 so the block still participates — NOT fee-per-byte 0, which
    // would drop it from the participant set and fork against C/Go/Py/Java/C# (§3.4).
    let div: i128 = if block_bytes == 0 { 1 } else { block_bytes as i128 };
    // signed clamp at 0 — a miner may under-claim (coinbase < subsidy)
    let fees: i128 = (coinbase_total as i128) - (subsidy as i128);
    let fees = if fees < 0 { 0 } else { fees };
    (fees / div) as u64
}

/// §3.4 participant median: P = the fee_per_byteᵢ ≥ 1 over the FEE_WINDOW blocks strictly
/// below h — membership decided AFTER the floor division (tiny fees flooring to 0, and
/// under-claims clamped to 0 by `fee_per_byte`, do NOT participate).
/// |P| < MIN_FEE_SAMPLE ⇒ rate = DUST_FLOOR exactly (degrade, don't extrapolate: a small
/// sample is spoofably cheap to own). Boundary INCLUSIVE — exactly MIN_FEE_SAMPLE
/// participants take the median path.
/// Else rate = clamp(sorted_P[(|P|−1)/2] × REF_SIZE, DUST_FLOOR, RATE_CAP): the LOWER
/// median — odd |P| ⇒ the true middle, even |P| ⇒ the lower of the two middles. Always an
/// observed element, never an average.
/// `window` is the per-block fee_per_byte for i ∈ [h−FEE_WINDOW, h−1] (exactly FEE_WINDOW long).
pub fn oracle_rate(window: &[u64]) -> u64 {
    let mut p: Vec<u64> = window.iter().copied().filter(|&v| v >= 1).collect();
    if p.len() < MIN_FEE_SAMPLE {
        return DUST_FLOOR;
    }
    p.sort_unstable();
    let median = p[(p.len() - 1) / 2];
    let scaled = (median as u128) * (REF_SIZE as u128);
    let clamped = scaled.clamp(DUST_FLOOR as u128, RATE_CAP as u128);
    clamped as u64
}

/// MTP(H) = median of timestamps[H−11 .. H−1] (11 blocks strictly before H), block H excluded.
/// Short window: k = min(11, H) predecessors; sort and select index ⌊k/2⌋ (upper-middle for
/// even k), never a two-value average. MTP(0) = 0.
/// `prev_timestamps` holds the timestamps of blocks 0..H-1 (index = height).
pub fn mtp(height: i64, prev_timestamps: &[i64]) -> i64 {
    if height <= 0 {
        return 0;
    }
    let h = height as usize;
    let k = 11usize.min(h);
    let lo = h - k; // first predecessor index
    let mut window: Vec<i64> = prev_timestamps[lo..h].to_vec();
    window.sort_unstable();
    window[k / 2]
}
