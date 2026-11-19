// Fee oracle (§3.4) + MTP (§5, conformance §2). Pure integer math, all bigint.
//
// The §5 generator INJECTS `rate` per block (rate = 28·(1+bounded(4))), so the SM fold does not run
// this oracle — it is the separate, spec-mandated stateless rate function, exercised by hand vectors
// here. (see SPEC-RATIONALE.md: the oracle vs the injected-rate model is a notable structural split.)
import { DUST_FLOOR, RATE_CAP, REF_SIZE, MIN_FEE_SAMPLE, DOGE_SUBSIDY } from "./constants.ts";

export type OracleBlock = { coinbaseTotal: bigint; blockBytes: bigint };

function clamp(v: bigint, lo: bigint, hi: bigint): bigint {
  return v < lo ? lo : v > hi ? hi : v;
}

// §3.4 participant median: feesᵢ = max(0, coinbase_total − subsidy)  [SIGNED ≥128-bit, clamp at 0 —
// a miner may under-claim]; fee_per_byteᵢ = ⌊feesᵢ / block_bytesᵢ⌋ [FLOOR]. The participant list P is
// the fee_per_byteᵢ ≥ 1 — membership decided AFTER the floor division (tiny fees flooring to 0 do
// not participate; an under-claim clamps to 0 fees = non-participant). |P| < MIN_FEE_SAMPLE
// (boundary INCLUSIVE — exactly MIN_FEE_SAMPLE takes the median path) degrades to DUST_FLOOR
// exactly; a small sample is spoofably cheap to own. Otherwise rate = clamp(sorted_P[⌊(|P|−1)/2⌋] ×
// REF_SIZE) — the LOWER median: odd |P| → the true middle, even |P| → the lower of the two middles.
// Always an observed element, never an average. subsidy is the flat 10_000-DOGE host value.
export function oracleRate(window: OracleBlock[]): bigint {
  const participants: bigint[] = [];
  for (const blk of window) {
    let fees = blk.coinbaseTotal - DOGE_SUBSIDY; // SIGNED — bigint never wraps
    if (fees < 0n) fees = 0n; // clamp under-claim to zero fees (else an unsigned wrap would spike it)
    // block_bytes is always ≥1 (a block has a coinbase tx); guard /0 with divisor 1
    // — NOT fee_per_byte 0 — to match C/Go/Py (else this block's participation forks).
    const b = blk.blockBytes > 0n ? blk.blockBytes : 1n;
    const perByte = fees / b; // FLOOR (bigint division)
    if (perByte >= 1n) participants.push(perByte); // fee-bearing blocks only
  }
  if (participants.length < MIN_FEE_SAMPLE) return DUST_FLOOR; // degrade, don't extrapolate
  const sorted = participants.slice().sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const median = sorted[(sorted.length - 1) >> 1]; // LOWER median (one index rule for any |P| ≥ 1)
  return clamp(median * REF_SIZE, DUST_FLOOR, RATE_CAP);
}

// §5 / conformance §2: MTP(H) = median (middle element, index ⌊k/2⌋ of sorted) of the timestamps of
// the ≤11 blocks STRICTLY before H — i.e. blocks [H−11 .. H−1], H's own timestamp excluded.
// blockTimestamps[i] = timestamp of block i. AMBIGUITY: for H=0 there are no predecessors; the prose
// (§5) assumes ≥11 exist. We define MTP(0)=0 and MTP for 1..10 over the few that exist (index ⌊k/2⌋).
export function computeMTP(blockTimestamps: bigint[], H: number): bigint {
  const lo = Math.max(0, H - 11);
  const window = blockTimestamps.slice(lo, H);
  if (window.length === 0) return 0n;
  const sorted = window.slice().sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return sorted[Math.floor(sorted.length / 2)];
}
