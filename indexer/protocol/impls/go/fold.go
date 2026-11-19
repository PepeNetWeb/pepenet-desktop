package main

import (
	"crypto/sha256"
	"sort"
)

// ---- abstract block/tx model fed to the fold ----
// The §5 fold consumes already-resolved identities + decoded carriers (§9). §4
// attribution is a separate shell (attrib.go). Identity carries (hash160, scriptType).

type Identity struct {
	h160 [20]byte
	styp byte // 0 = P2PKH, 1 = P2SH  (numeric encoding not pinned by spec; logged)
	ok   bool // passed §4 + SIGHASH_ALL
}

type FoldOutput struct {
	h160  [20]byte
	styp  byte
	value uint64
}

type FoldCarrier struct {
	c     Carrier
	value uint64 // the OP_RETURN output's own value
	vout  uint32 // serialized output index
}

type FoldTx struct {
	txIndex  uint32
	inputs   []Identity
	carriers []FoldCarrier // vout order
	spend    []FoldOutput  // spendable outputs, vout order (consume-once pool)
}

type FoldBlock struct {
	height int64
	mtp    int64
	rate   uint64
	txs    []FoldTx
}

// applyBlock runs pre-block time transitions then the block's txs (§5).
func (s *FoldState) applyBlock(b FoldBlock) {
	s.curHeight = b.height
	s.scratch = map[string]claimScratch{} // begin_block: reset, never digested
	s.preBlock(b.height, b.mtp)
	for _, tx := range b.txs {
		s.applyTx(b, tx)
	}
}

// preBlock: time-triggered transitions before txs, type-order reserve→offer→lease,
// each idempotent; then COMMIT_EXPIRY prune. Bounds are exclusive (owned iff MTP <
// lease_expiry); the COMMIT window is inclusive.
func (s *FoldState) preBlock(height, mtp int64) {
	// Iterate names in deterministic (sorted) order so any bump ordering is stable.
	for _, name := range s.sortedNameKeys() {
		r := s.names[name]
		if r == nil {
			continue
		}
		// reserve revert
		if r.st == ST_RESERVED && mtp >= r.reserveExpiry {
			r.st = ST_LISTED
			// physically reset reserve-only fields, keep listing fields
			r.buyer = [20]byte{}
			r.burnLeg = 0
			r.payLeg = 0
			r.reserveExpiry = 0
		}
		// offer close (open listing or directed offer) → OWNED
		if (r.st == ST_LISTED || r.st == ST_OFFERED) && mtp >= r.offerExpiry {
			r.st = ST_OWNED
			r.resetMarket()
		}
		// lease lapse → remove from owner's set; bump owner mutation to H
		if mtp >= r.leaseExpiry {
			owner := r.owner
			delete(s.names, name)
			s.bumpMut(owner, height)
		}
	}
	// COMMIT_EXPIRY prune (inclusive window): drop where mtp > commit_time + COMMIT_EXPIRY
	kept := s.commits[:0]
	for _, c := range s.commits {
		if mtp > c.commitTime+COMMIT_EXPIRY {
			continue
		}
		kept = append(kept, c)
	}
	s.commits = kept
}

func (s *FoldState) sortedNameKeys() []string {
	keys := make([]string, 0, len(s.names))
	for k := range s.names {
		keys = append(keys, k)
	}
	sort.Strings(keys) // ascending raw-byte order
	return keys
}

// applyTx: a single forward pass over carriers in vout order with the acting
// identity. Consensus classifies no content — only name-action carriers mutate state.
func (s *FoldState) applyTx(b FoldBlock, tx FoldTx) {
	var actor Identity
	if len(tx.inputs) > 0 {
		actor = tx.inputs[0]
	}
	consumed := make([]bool, len(tx.spend))

	for _, fc := range tx.carriers {
		c := fc.c
		if c.kind != ACTION {
			continue // IGNORE (or anything non-action)
		}
		op := c.opcode
		// forward-only activation gate (§3.0): all ops gate at one height.
		if b.height < ACTIVATION_HEIGHT {
			continue
		}
		switch op {
		case OP_AS:
			k := c.asIndex
			if k >= 0 && k < len(tx.inputs) && tx.inputs[k].ok {
				actor = tx.inputs[k]
			} else {
				actor = Identity{ok: false}
			}
			continue
		case OP_TRADE:
			// attributed to its own named inputs, NOT the acting identity.
			s.dispatchTrade(b, tx, c)
			continue
		}
		// every other op: requires a valid acting identity
		if !actor.ok {
			continue
		}
		s.dispatchAction(b, tx, &fc, actor, consumed)
	}
}

func (s *FoldState) dispatchAction(b FoldBlock, tx FoldTx, fc *FoldCarrier, actor Identity, consumed []bool) {
	c := fc.c
	switch c.opcode {
	case OP_COMMIT:
		s.commits = append(s.commits, CommitRow{
			commitment: c.commit, height: b.height, txIndex: tx.txIndex, commitTime: b.mtp,
		})

	case OP_CLAIM:
		s.applyClaim(b, tx, fc, actor)

	case OP_RENEW:
		s.applyRenew(b, fc, actor)

	case OP_TRANSFER:
		s.applyTransfer(b, c, actor)

	case OP_RELEASE:
		s.applyRelease(b, c, actor)

	case OP_RENEW_NAME:
		s.applyRenewName(b, fc, actor)

	case OP_TRANSFER_NAME:
		s.applyTransferName(b, c, actor)

	case OP_RELEASE_NAME:
		s.applyReleaseName(b, c, actor)

	case OP_SELL:
		s.applySell(b, c, actor)

	case OP_RESERVE:
		s.applyReserve(b, tx, fc.value, c, actor, consumed)

	case OP_SETTLE:
		s.applySettle(b, tx, c, actor, consumed)

	case OP_SELL_TO:
		s.applySellTo(b, c, actor)

	case OP_PAY:
		s.applyPay(b, tx, c, actor, consumed)
	}
}

func (s *FoldState) applyClaim(b FoldBlock, tx FoldTx, fc *FoldCarrier, actor Identity) {
	name := string(fc.c.name)
	// backing commit: SHA256(salt ‖ name ‖ author_h160), commit_height < claim_height, live.
	var want [32]byte
	{
		buf := make([]byte, 0, 32+len(fc.c.name)+20)
		buf = append(buf, fc.c.salt[:]...)
		buf = append(buf, fc.c.name...)
		buf = append(buf, actor.h160[:]...)
		want = sha256.Sum256(buf)
	}
	bestCH := int64(-1)
	bestTI := uint32(0)
	found := false
	for _, cm := range s.commits {
		if cm.commitment != want {
			continue
		}
		if cm.height >= b.height { // must be strictly earlier block
			continue
		}
		// liveness: not pruned (mtp <= commit_time+COMMIT_EXPIRY guaranteed by preBlock);
		// commit_time <= mtp by MTP monotonicity. Both hold for surviving rows.
		if !found || cm.height < bestCH || (cm.height == bestCH && cm.txIndex < bestTI) {
			bestCH = cm.height
			bestTI = cm.txIndex
			found = true
		}
	}
	if !found {
		return // no live ≥1-deep commit → drop (no FCFS)
	}

	// already owned?
	if r, ok := s.names[name]; ok {
		// is it a fresh same-block mint? (claim scratch)
		sc, isFresh := s.scratch[name]
		if !isFresh {
			return // owned from a prior context → drop
		}
		// same-block displacement: displace iff (bestCH,bestTI) lex-smaller AND still that owner's fresh OWNED mint
		if r.st != ST_OWNED || r.owner != sc.owner {
			return
		}
		if bestCH < sc.ch || (bestCH == sc.ch && bestTI < sc.ti) {
			// displace
			add := leaseDaysSingle(fc.value, b.rate, b.mtp, b.mtp)
			if add == 0 {
				return // T==0 fail-closed (shouldn't reach: value gate)
			}
			r.owner = actor.h160
			r.leaseExpiry = b.mtp + add*BILLING_UNIT
			s.scratch[name] = claimScratch{ch: bestCH, ti: bestTI, owner: actor.h160}
			s.bumpMut(actor.h160, b.height)
		}
		return
	}

	// fresh mint
	add := leaseDaysSingle(fc.value, b.rate, b.mtp, b.mtp)
	if add == 0 {
		return // must cover ≥1 day
	}
	s.names[name] = &NameRow{owner: actor.h160, st: ST_OWNED, leaseExpiry: b.mtp + add*BILLING_UNIT}
	if s.scratch == nil {
		s.scratch = map[string]claimScratch{}
	}
	s.scratch[name] = claimScratch{ch: bestCH, ti: bestTI, owner: actor.h160}
	s.bumpMut(actor.h160, b.height)
}

// leaseDaysSingle computes the water-filled days for a single fresh/displaced name
// (headroom = full 365 from `now`). Returns days to add (capped to headroom).
func leaseDaysSingle(burn, rate uint64, expiry, now int64) int64 {
	T, huge := leaseT(burn, rate)
	if !huge && T == 0 {
		return 0
	}
	h := headroomDays(expiry, now)
	if huge || T >= uint64(h) {
		return h
	}
	return int64(T)
}

// leaseT computes T = ⌊burn·LEASE_QUANTUM / (rate·BILLING_UNIT)⌋ in 128-bit.
// Returns (T, huge) where huge means T >= 2^64 (clamp to total headroom).
func leaseT(burn, rate uint64) (uint64, bool) {
	hi, lo := mul64(burn, LEASE_QUANTUM)
	den := rate * BILLING_UNIT // rate<=1e8, BILLING_UNIT=86400 → <8.7e12, fits u64
	if den == 0 {
		return 0, false
	}
	if hi >= den {
		return 0, true // quotient >= 2^64
	}
	return div128by64(hi, lo, den), false
}

func headroomDays(expiry, now int64) int64 {
	rem := expiry - now
	if rem < 0 {
		rem = 0
	}
	h := (MAX_LEASE - rem) / BILLING_UNIT
	if h < 0 {
		h = 0
	}
	return h
}
