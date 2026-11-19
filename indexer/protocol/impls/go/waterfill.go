package main

// waterFill spreads T name·days across the selected name rows (§3.5):
//   - headroom hᵢ = ⌊(MAX_LEASE − (expiryᵢ − now)) / BILLING_UNIT⌋ days
//   - zero-headroom names are skipped (never counted, never awarded)
//   - even level λ = max λ with Σ min(hᵢ,λ) ≤ T; remainder +1 day to the first
//     headroom-having (hᵢ>λ) names in ascending-lex order
//   - all-capped surplus (T ≥ Σh) is forfeited
// names[i] corresponds to keys[i] (ascending-lex already, from ownedSorted).
func waterFill(rows []*NameRow, keys []string, T uint64, huge bool, now int64) {
	// headrooms
	h := make([]int64, len(rows))
	var totalH uint64
	maxH := int64(0)
	for i, r := range rows {
		h[i] = headroomDays(r.leaseExpiry, now)
		totalH += uint64(h[i])
		if h[i] > maxH {
			maxH = h[i]
		}
	}

	// All-cap regime: T ≥ Σh (or T overflowed 64-bit) ⇒ every name takes its full
	// headroom, surplus forfeited.
	if huge || T >= totalH {
		for i, r := range rows {
			r.leaseExpiry += h[i] * BILLING_UNIT
		}
		return
	}

	// Find max λ ∈ [0, maxH] with sumMin(λ) ≤ T. maxH ≤ 365 so a linear scan is fine.
	lam := int64(0)
	for lam < maxH {
		if sumMin(h, lam+1) <= T {
			lam++
		} else {
			break
		}
	}
	base := sumMin(h, lam)
	R := T - base // remainder, < count(hᵢ>λ)

	// +1 to the first R names with hᵢ > λ, ascending-lex (rows already lex-ordered).
	for i, r := range rows {
		add := minI64(h[i], lam)
		if R > 0 && h[i] > lam {
			add++
			R--
		}
		r.leaseExpiry += add * BILLING_UNIT
	}
}

func sumMin(h []int64, lam int64) uint64 {
	var s uint64
	for _, hi := range h {
		if hi < lam {
			s += uint64(hi)
		} else {
			s += uint64(lam)
		}
	}
	return s
}

func minI64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
