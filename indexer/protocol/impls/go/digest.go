package main

import (
	"bytes"
	"crypto/sha256"
	"sort"
)

// stateDigest serializes the live state into the canonical byte layout pinned by
// SPEC-conformance.md §4 and returns its SHA-256. All multi-byte ints little-endian;
// signed values two's-complement LE. Magic "SMv1". Tables: names, commits, muts
// (names-only SM — votes/posts/decorations/overflow removed). Collections are
// emitted in the pinned sort order — NEVER Go map iteration order.
func (s *FoldState) stateDigest() [32]byte {
	var b bytes.Buffer
	b.WriteString("SMv1")

	// names — sorted ascending by raw name bytes
	nameKeys := make([]string, 0, len(s.names))
	for k := range s.names {
		nameKeys = append(nameKeys, k)
	}
	sort.Strings(nameKeys)
	wU32(&b, uint32(len(nameKeys)))
	for _, k := range nameKeys {
		r := s.names[k]
		b.WriteByte(byte(len(k)))
		b.WriteString(k)
		b.Write(r.owner[:])
		b.WriteByte(byte(r.st))
		wI64(&b, r.leaseExpiry)
		b.Write(r.seller[:])
		b.WriteByte(r.sellerType)
		wU64(&b, r.price)
		wI64(&b, r.offerExpiry)
		b.Write(r.buyer[:])
		wU64(&b, r.burnLeg)
		wU64(&b, r.payLeg)
		wI64(&b, r.reserveExpiry)
	}

	// commits — sorted by (commitment[32], commit_height, tx_index): total order
	commits := append([]CommitRow(nil), s.commits...)
	sort.Slice(commits, func(i, j int) bool {
		if c := bytes.Compare(commits[i].commitment[:], commits[j].commitment[:]); c != 0 {
			return c < 0
		}
		if commits[i].height != commits[j].height {
			return commits[i].height < commits[j].height
		}
		return commits[i].txIndex < commits[j].txIndex
	})
	wU32(&b, uint32(len(commits)))
	for _, c := range commits {
		b.Write(c.commitment[:])
		wI64(&b, c.height)
		wU32(&b, c.txIndex)
		wI64(&b, c.commitTime)
	}

	// muts — sorted by owner bytes
	owners := make([][20]byte, 0, len(s.muts))
	for o := range s.muts {
		owners = append(owners, o)
	}
	sort.Slice(owners, func(i, j int) bool {
		return bytes.Compare(owners[i][:], owners[j][:]) < 0
	})
	wU32(&b, uint32(len(owners)))
	for _, o := range owners {
		b.Write(o[:])
		wI64(&b, s.muts[o])
	}

	return sha256.Sum256(b.Bytes())
}

func wU32(b *bytes.Buffer, v uint32) {
	b.Write([]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)})
}
func wU64(b *bytes.Buffer, v uint64) {
	var t [8]byte
	for i := 0; i < 8; i++ {
		t[i] = byte(v >> (8 * uint(i)))
	}
	b.Write(t[:])
}
func wI64(b *bytes.Buffer, v int64) { wU64(b, uint64(v)) }
