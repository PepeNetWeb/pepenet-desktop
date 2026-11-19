package main

// §3.4 coinbase fee oracle — the "participant median". A pure function the
// harness feeds into a block's `rate`; the fold itself takes (mtp, rate) as
// givens, so statelessness/chain-abstraction holds (the soak generator keeps
// injecting rates directly). Every step is fixed-width integer math with the
// under-claim clamp, the fee-bearing participant filter (MIN_FEE_SAMPLE
// degrade), and the lower-median single-element index rule pinned.

import "sort"

// oracleRate computes rate over a window of (coinbase, subsidy, block_bytes)
// triples:
//
//	fee_per_byte_i = ⌊max(0, coinbase_i − subsidy_i) / block_bytes_i⌋
//	P              = { fee_per_byte_i : fee_per_byte_i ≥ 1 }           (participants)
//	|P| < MIN_FEE_SAMPLE ⇒ DUST_FLOOR exactly (boundary INCLUSIVE:
//	                       exactly MIN_FEE_SAMPLE participants take the median)
//	else rate = clamp(sorted_P[(|P|−1)/2] · REF_SIZE, DUST_FLOOR, RATE_CAP)
func oracleRate(coinbase, subsidy, blockBytes []int64) uint64 {
	n := len(coinbase)
	if n <= 0 || len(subsidy) != n || len(blockBytes) != n {
		return DUST_FLOOR
	}
	fpb := make([]uint64, 0, n)
	for i := 0; i < n; i++ {
		// fees = max(0, coinbase − subsidy), SIGNED semantics: a miner may
		// under-claim (coinbase < subsidy); a raw unsigned subtraction would wrap
		// to ~2^64 and wrongly enroll the block as a huge participant. Clamp at
		// 0 → an under-claim reads as 0 fees, i.e. a NON-participant. The `>`
		// gate makes the wraparound subtraction exact: the true difference of
		// two int64s lies in (0, 2^64) here, so it fits uint64 without wrap
		// (Go's 128-bit-free stand-in for the C reference's __int128 leg).
		if coinbase[i] <= subsidy[i] {
			continue
		}
		fees := uint64(coinbase[i]) - uint64(subsidy[i])
		b := blockBytes[i]
		if b <= 0 { // division guard — MANDATORY (conformance §2; see leaseT)
			b = 1
		}
		v := fees / uint64(b) // floor, whole koinu/byte
		// §3.4 participant list P: fee-bearing blocks only, membership decided
		// AFTER the floor division (tiny fees flooring to 0 do not participate).
		if v >= 1 {
			fpb = append(fpb, v)
		}
	}
	// Degrade, don't extrapolate: a small sample is spoofably cheap to own.
	// Boundary INCLUSIVE — exactly MIN_FEE_SAMPLE participants take the median.
	if len(fpb) < MIN_FEE_SAMPLE {
		return DUST_FLOOR
	}
	sort.Slice(fpb, func(i, j int) bool { return fpb[i] < fpb[j] })
	// LOWER median, one index rule for any |P| ≥ 1: odd → the true middle; even →
	// the lower of the two middles. Always an observed element, never an average —
	// no rounding rule exists for indexers to split on.
	med := fpb[(len(fpb)-1)/2]
	hi, lo := mul64(med, REF_SIZE) // med can be ~2^64 → scale in 128-bit
	if hi != 0 || lo > RATE_CAP {  // cap (bounds miner grief)
		return RATE_CAP
	}
	if lo < DUST_FLOOR { // floor (defensive; med ≥ 1 here)
		return DUST_FLOOR
	}
	return lo
}
