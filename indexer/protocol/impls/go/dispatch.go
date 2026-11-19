package main

import "sort"

// ownedSorted returns the actor's owned names in ascending raw-byte order (the
// bitmap ordering, §3.5). Includes LISTED/OFFERED/RESERVED rows (still owned).
func (s *FoldState) ownedSorted(owner [20]byte) []string {
	var ns []string
	for k, r := range s.names {
		if r.owner == owner {
			ns = append(ns, k)
		}
	}
	sort.Strings(ns)
	return ns
}

// bitSet reads bit i LSB-first within each flag byte.
func bitSet(flags []byte, i int) bool {
	bi := i >> 3
	if bi >= len(flags) {
		return false
	}
	return (flags[bi]>>(uint(i)&7))&1 == 1
}

// anchorOK validates the renew/transfer/release anchor guard (§3.5):
// last_mutation ≤ H ≤ confirm_height and confirm_height − H ≤ MAX_ANCHOR_AGE.
func (s *FoldState) anchorOK(owner [20]byte, anchor, confirm int64) bool {
	if anchor < 0 || anchor > confirm {
		return false
	}
	if confirm-anchor > MAX_ANCHOR_AGE {
		return false
	}
	last := s.muts[owner] // 0 if none
	return last <= anchor
}

// selectBitmap returns the owned-set names selected by the bitmap (or all if flags==nil).
// out-of-bounds bits (index ≥ K) are ignored.
func selectBitmap(owned []string, flags []byte) []string {
	if flags == nil {
		return owned
	}
	var sel []string
	for i, nm := range owned {
		if bitSet(flags, i) {
			sel = append(sel, nm)
		}
	}
	return sel
}

func (s *FoldState) applyRenew(b FoldBlock, fc *FoldCarrier, actor Identity) {
	c := fc.c
	owned := s.ownedSorted(actor.h160)
	if c.hasAnchor {
		if !s.anchorOK(actor.h160, c.anchor, b.height) {
			return // reject-and-resend
		}
	}
	sel := selectBitmap(owned, c.flags)
	if len(sel) == 0 {
		return
	}
	// RENEW has no locked-skip exception: listed/offered names still renew.
	rows := make([]*NameRow, len(sel))
	for i, nm := range sel {
		rows[i] = s.names[nm]
	}
	// T≥1 gate (fail-closed at T=0).
	T, huge := leaseT(fc.value, b.rate)
	if !huge && T == 0 {
		return
	}
	waterFill(rows, sel, T, huge, b.mtp)
	// RENEW is NOT a set mutation → no bump.
}

func (s *FoldState) applyTransfer(b FoldBlock, c Carrier, actor Identity) {
	owned := s.ownedSorted(actor.h160)
	if c.hasAnchor {
		if !s.anchorOK(actor.h160, c.anchor, b.height) {
			return
		}
	}
	sel := selectBitmap(owned, c.flags)
	moved := false
	for _, nm := range sel {
		r := s.names[nm]
		if r.st != ST_OWNED { // locked (listed/offered/reserved) → skip
			continue
		}
		r.owner = c.target
		moved = true
	}
	if moved {
		s.bumpMut(actor.h160, b.height)
		s.bumpMut(c.target, b.height)
	}
}

func (s *FoldState) applyRelease(b FoldBlock, c Carrier, actor Identity) {
	owned := s.ownedSorted(actor.h160)
	if !s.anchorOK(actor.h160, c.anchor, b.height) {
		return
	}
	sel := selectBitmap(owned, c.flags)
	removed := false
	for _, nm := range sel {
		r := s.names[nm]
		if r.st != ST_OWNED { // locked → skip
			continue
		}
		delete(s.names, nm)
		removed = true
	}
	if removed {
		s.bumpMut(actor.h160, b.height)
	}
}

// ── the by-name forms (§3.5) — the singleton siblings of the bitmap ops ──────
// A name string is its own position-independent address into the owned set, so
// there is no anchor and no anchor guard. The name MUST be in the actor's owned
// set (same membership as ownedSorted: LISTED/OFFERED/RESERVED rows included,
// owner stays the seller until settle/pay); else drop.

// findMine returns the row for c.name iff the actor controls it, else nil.
func (s *FoldState) findMine(c Carrier, actor Identity) (string, *NameRow) {
	nm := string(c.name)
	r := s.names[nm]
	if r == nil || r.owner != actor.h160 {
		return nm, nil
	}
	return nm, r
}

// applyRenewName water-fills the singleton set; listed/offered names are still
// renewable by their seller. Renewal is not a set mutation → no bump.
func (s *FoldState) applyRenewName(b FoldBlock, fc *FoldCarrier, actor Identity) {
	nm, r := s.findMine(fc.c, actor)
	if r == nil {
		return
	}
	T, huge := leaseT(fc.value, b.rate)
	if !huge && T == 0 {
		return // fail-closed at T=0
	}
	waterFill([]*NameRow{r}, []string{nm}, T, huge, b.mtp)
}

// applyTransferName gifts exactly one owned (unlocked) name; lease conveys.
// Locked → no-op, no bump. A move bumps BOTH parties (self-target included).
func (s *FoldState) applyTransferName(b FoldBlock, c Carrier, actor Identity) {
	_, r := s.findMine(c, actor)
	if r == nil || r.st != ST_OWNED { // absent / not mine / locked
		return
	}
	r.owner = c.target
	s.bumpMut(actor.h160, b.height)
	s.bumpMut(c.target, b.height)
}

// applyReleaseName returns exactly one owned (unlocked) name to the pool now.
// Locked → no-op, no bump.
func (s *FoldState) applyReleaseName(b FoldBlock, c Carrier, actor Identity) {
	nm, r := s.findMine(c, actor)
	if r == nil || r.st != ST_OWNED {
		return
	}
	delete(s.names, nm)
	s.bumpMut(actor.h160, b.height)
}

func (s *FoldState) applySell(b FoldBlock, c Carrier, actor Identity) {
	nm := string(c.name)
	r := s.names[nm]
	if r == nil || r.owner != actor.h160 || r.st != ST_OWNED {
		return // must own and be unlocked
	}
	if c.price < 3*DUST_FLOOR {
		return
	}
	window := int64(c.window)
	if window == 0 {
		window = RESERVE_WINDOW
	} else if window < RESERVE_WINDOW {
		return // nonzero but below floor → ignore
	}
	// add-form upper bound: MTP_now + window + REORG_BUFFER ≤ lease_expiry (unsigned add).
	if b.mtp+window+REORG_BUFFER > r.leaseExpiry {
		return
	}
	r.st = ST_LISTED
	r.seller = actor.h160
	r.sellerType = actor.styp
	r.price = c.price
	r.offerExpiry = b.mtp + window
	// SELL is not a set mutation → no bump.
}

func (s *FoldState) applySellTo(b FoldBlock, c Carrier, actor Identity) {
	nm := string(c.name)
	r := s.names[nm]
	if r == nil || r.owner != actor.h160 || r.st != ST_OWNED {
		return
	}
	if c.price < DUST_FLOOR {
		return
	}
	if b.mtp+DIRECT_WINDOW+REORG_BUFFER > r.leaseExpiry {
		return
	}
	r.st = ST_OFFERED
	r.seller = actor.h160
	r.sellerType = actor.styp
	r.price = c.price
	r.buyer = c.buyer
	r.offerExpiry = b.mtp + DIRECT_WINDOW
	// not a set mutation → no bump.
}

func (s *FoldState) applyReserve(b FoldBlock, tx FoldTx, carrierValue uint64, c Carrier, actor Identity, consumed []bool) {
	nm := string(c.name)
	r := s.names[nm]
	if r == nil || r.st != ST_LISTED {
		return // not an open listing (already reserved / not listed) → drop
	}
	burnLeg := depositLeg(r.price, RESERVE_BURN_BPS)
	payLeg := depositLeg(r.price, RESERVE_PAY_BPS)
	// carrier value (the burn rides in the RESERVE's own OP_RETURN value) must cover burn_leg.
	if carrierValue < burnLeg {
		return
	}
	// pay_leg output to seller must be present (consume-once exact match).
	idx := matchOutput(tx, consumed, r.seller, r.sellerType, payLeg)
	if idx < 0 {
		return
	}
	consumed[idx] = true
	r.st = ST_RESERVED
	r.buyer = actor.h160
	r.burnLeg = burnLeg
	r.payLeg = payLeg
	re := b.mtp + RESERVE_WINDOW
	if re > r.offerExpiry { // clamp to offer_expiry (load-bearing)
		re = r.offerExpiry
	}
	r.reserveExpiry = re
	// RESERVE is not a set mutation → no bump.
}

func (s *FoldState) applySettle(b FoldBlock, tx FoldTx, c Carrier, actor Identity, consumed []bool) {
	nm := string(c.name)
	r := s.names[nm]
	if r == nil || r.st != ST_RESERVED {
		return
	}
	if r.buyer != actor.h160 {
		return // only the exclusive reserver may settle
	}
	if b.mtp >= r.reserveExpiry {
		return // MTP < reserve_expiry
	}
	remainder := r.price - r.burnLeg - r.payLeg // ≥ DUST_FLOOR by SELL floor
	idx := matchOutput(tx, consumed, r.seller, r.sellerType, remainder)
	if idx < 0 {
		return
	}
	consumed[idx] = true
	seller := r.seller
	r.owner = actor.h160
	r.st = ST_OWNED
	r.resetMarket() // lease conveys (leaseExpiry unchanged)
	s.bumpMut(actor.h160, b.height)
	s.bumpMut(seller, b.height)
}

func (s *FoldState) applyPay(b FoldBlock, tx FoldTx, c Carrier, actor Identity, consumed []bool) {
	nm := string(c.name)
	r := s.names[nm]
	if r == nil || r.st != ST_OFFERED {
		return
	}
	if r.buyer != actor.h160 {
		return // only the named buyer
	}
	if b.mtp >= r.offerExpiry {
		return
	}
	idx := matchOutput(tx, consumed, r.seller, r.sellerType, r.price)
	if idx < 0 {
		return
	}
	consumed[idx] = true
	seller := r.seller
	r.owner = actor.h160
	r.st = ST_OWNED
	r.resetMarket()
	s.bumpMut(actor.h160, b.height)
	s.bumpMut(seller, b.height)
}

func (s *FoldState) dispatchTrade(b FoldBlock, tx FoldTx, c Carrier) {
	ia, ib := c.idxA, c.idxB
	if ia < 0 || ib < 0 || ia >= len(tx.inputs) || ib >= len(tx.inputs) {
		return
	}
	if ia == ib {
		return
	}
	pa, pb := tx.inputs[ia], tx.inputs[ib]
	if !pa.ok || !pb.ok {
		return
	}
	na, nb := string(c.nameA), string(c.nameB)
	if na == nb {
		return
	}
	ra := s.names[na]
	rb := s.names[nb]
	if ra == nil || rb == nil {
		return
	}
	if ra.owner != pa.h160 || rb.owner != pb.h160 {
		return
	}
	if ra.st != ST_OWNED || rb.st != ST_OWNED { // both must be unlocked
		return
	}
	// atomic swap; leases convey
	ra.owner = pb.h160
	rb.owner = pa.h160
	s.bumpMut(pa.h160, b.height)
	s.bumpMut(pb.h160, b.height)
}

// depositLeg = max(DUST_FLOOR, ⌊price·bps/10000⌋) in 128-bit (§3.7).
func depositLeg(price uint64, bps uint64) uint64 {
	hi, lo := mul64(price, bps)
	// hi ≤ bps-1 ≤ 99 < 10000, so div128by64's hi<den precondition holds.
	q := div128by64(hi, lo, 10000)
	if q < DUST_FLOOR {
		return DUST_FLOOR
	}
	return q
}

// matchOutput finds the lowest-vout not-yet-consumed spendable output whose
// (hash160, scriptType, value) == (seller, sellerType, owed). Returns index or -1.
func matchOutput(tx FoldTx, consumed []bool, seller [20]byte, styp byte, owed uint64) int {
	for i, o := range tx.spend {
		if consumed[i] {
			continue
		}
		if o.h160 == seller && o.styp == styp && o.value == owed {
			return i
		}
	}
	return -1
}

