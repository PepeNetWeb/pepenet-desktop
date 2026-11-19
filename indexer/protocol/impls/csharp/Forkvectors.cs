using System;
using System.Collections.Generic;
using System.Linq;

namespace Pepenet;

/// <summary>
/// forkvectors — the prose-pinned consensus-fork differential vectors (Tier 2).
///
/// This impl uses its OWN generator (not gen.c), so it cannot reproduce the
/// byte-for-byte seed soak (§5/§6). Instead it cross-validates exactly what the
/// PROSE pins: each independent reference impl must independently reproduce the
/// spec-mandated outcome for every consensus-critical vector. See
/// SPEC-conformance.md §"Two conformance tiers".
///
/// Vectors (the same set every reference impl carries):
///   TV-1  COMMIT_EXPIRY boundary is INCLUSIVE (live through commit_time+EXPIRY)
///   TV-5b claim multiplicity — the MINIMUM backing commit tx_index wins
///   TV-6  selection bitmap is LSB-first
///   TV-7  a lapse bumps the owner's set-mutation height → a stale-anchored RENEW drops
///   TV-8  a locked (LISTED) name is selectively skipped, not freed
///   M9    TRADE settles via its named parties even when vin[0] (acting id) is ⊥
///   H8    a used commit lingers in the table until the COMMIT_EXPIRY prune
///   H3    a set-mutation row persists after the owner's set empties
///
/// Each vector asserts the outcome; the runner greps for "0 diverge".
/// </summary>
public static class Forkvectors
{
    private static int _match, _diverge;

    private static void Check(bool cond, string vec, string msg)
    {
        if (cond) _match++;
        else { _diverge++; Console.WriteLine($"DIVERGE {vec}: {msg}"); }
    }

    private const long T0 = 1_000_000;

    public static int Run()
    {
        _match = 0; _diverge = 0;
        TV1(); TV5b(); TV6(); TV7(); TV8(); M9(); H8(); H3();
        Console.WriteLine($"forkvectors: {_match} match, {_diverge} diverge");
        return _diverge == 0 ? 0 : 1;
    }

    // ---------------- builders ----------------

    private static Tx Tx(IEnumerable<Input> ins, IEnumerable<Out> outs)
        => new() { Inputs = ins.ToList(), Outputs = outs.ToList() };

    // rate = 28 ⇒ burn N koinu = N name-days (LEASE_QUANTUM / BILLING_UNIT = 28).
    private static Block Blk(long h, long mtp, params Tx[] txs)
        => new() { Height = h, Mtp = mtp, Rate = 28, Txs = txs.ToList() };

    private static Tx Tx1(int id, ulong carrierValue, byte[] payload)
        => Tx(new[] { B.In(id) }, new[] { Out.Carrier(payload, carrierValue) });

    private static byte[] CommitPayload(byte saltB, string name, int authorId)
        => B.Commit(B.Commitment(B.Salt(saltB), B.Name(name), B.Id(authorId)));

    private static Tx CommitTx(int id, byte saltB, string name)
        => Tx1(id, 0, CommitPayload(saltB, name, id));

    private static Tx ClaimTx(int id, ulong days, byte saltB, string name)
        => Tx1(id, days, B.Claim(B.Salt(saltB), name));

    // ⊥ input: a vin that failed §4 / does not sign SIGHASH_ALL (acting identity is ⊥).
    private static Input BottomIn() => new() { H160 = new byte[20], Type = K.TYPE_P2PKH, SighashAll = false };

    private static bool OwnedBy(Fold f, string name, int id)
        => f.Names.TryGetValue(name, out var r) && r.Owner.SequenceEqual(B.Id(id));

    private static long? Mut(Fold f, int id)
        => f.Muts.TryGetValue(Hashing.Hex(B.Id(id)), out var m) ? m : null;

    // mint n0,n1,n2 owned by `id` (commit block 1, claim block 2 with long leases); id.mut = 2.
    private static Fold ClaimThree(int id)
    {
        var f = new Fold();
        f.ApplyBlock(Blk(1, T0,
            CommitTx(id, 0x60, "n0"),
            CommitTx(id, 0x61, "n1"),
            CommitTx(id, 0x62, "n2")));
        f.ApplyBlock(Blk(2, T0 + 300,
            ClaimTx(id, 365, 0x60, "n0"),
            ClaimTx(id, 365, 0x61, "n1"),
            ClaimTx(id, 365, 0x62, "n2")));
        return f;
    }

    // ---------------- vectors ----------------

    // TV-1: the COMMIT_EXPIRY window is INCLUSIVE. A claim at MTP == commit_time +
    // COMMIT_EXPIRY still sees a live commit; one tick later the pre-block prune has
    // removed it and the claim drops.
    private static void TV1()
    {
        Fold Build(long claimMtp)
        {
            var f = new Fold();
            f.ApplyBlock(Blk(1, T0, CommitTx(1, 0x11, "alpha")));
            f.ApplyBlock(Blk(2, claimMtp, ClaimTx(1, 30, 0x11, "alpha")));
            return f;
        }
        var sOK = Build(T0 + K.COMMIT_EXPIRY);
        Check(OwnedBy(sOK, "alpha", 1), "TV-1", "claim at commit_time+COMMIT_EXPIRY must succeed (inclusive window)");
        var sNo = Build(T0 + K.COMMIT_EXPIRY + 1);
        Check(!sNo.Names.ContainsKey("alpha"), "TV-1", "claim one tick past the window must drop (commit pruned)");
    }

    // TV-5b: an author may post the same commitment multiple times; the claim's
    // priority uses the MINIMUM backing commit tx_index, so A (commits at tx0 & tx2)
    // displaces B (commit at tx1) even though B's claim is applied first.
    private static void TV5b()
    {
        var f = new Fold();
        f.ApplyBlock(Blk(1, T0,
            CommitTx(1, 0xAA, "hot"),   // A (Id1) commit tx_index 0
            CommitTx(2, 0xBB, "hot"),   // B (Id2) commit tx_index 1
            CommitTx(1, 0xAA, "hot"))); // A duplicate commit tx_index 2 (identical commitment bytes)
        f.ApplyBlock(Blk(2, T0 + 300,
            ClaimTx(2, 30, 0xBB, "hot"),  // B claims first
            ClaimTx(1, 30, 0xAA, "hot"))); // A displaces — min backing commit tx_index 0 < 1
        Check(OwnedBy(f, "hot", 1), "TV-5b", "minimum backing commit tx_index (A=0) wins, not max (2) or claim order");
    }

    // TV-6: the selection bitmap is LSB-first. flags=0x05 selects bits 0 and 2.
    private static void TV6()
    {
        var f = ClaimThree(1); // Id1 owns n0,n1,n2 (lex order); Id1.mut = 2
        f.ApplyBlock(Blk(3, T0 + 600, Tx1(1, 0, B.TransferSel(B.Id(2), 2, new byte[] { 0x05 }))));
        Check(OwnedBy(f, "n0", 2) && OwnedBy(f, "n2", 2) && OwnedBy(f, "n1", 1),
            "TV-6", "flags=0x05 selects n0,n2 (LSB-first); an MSB-first reader forks");
    }

    // TV-7: a lapse in the pre-block phase bumps the owner's last_set_mutation_height
    // to the connecting height, so a RENEW carrying a stale anchor (valid before the
    // lapse) fails the anchor guard and drops — the name's lease is unchanged.
    private static void TV7()
    {
        var f = new Fold();
        f.ApplyBlock(Blk(1, T0,
            CommitTx(1, 0x40, "n0"),
            CommitTx(1, 0x41, "n1")));
        // n0 gets a 1-day lease; n1 a 300-day lease. Id1.mut = 2.
        f.ApplyBlock(Blk(2, T0 + 300,
            ClaimTx(1, 1, 0x40, "n0"),
            ClaimTx(1, 300, 0x41, "n1")));
        long n1Before = f.Names["n1"].LeaseExpiry;
        // block 3 at n0's expiry: pre-block lapses n0 → bumps Id1.mut to 3. In the same
        // block Id1 submits an all-safe RENEW anchored at height 2 (the pre-lapse set).
        long lapseMtp = (T0 + 300) + 1 * K.BILLING_UNIT;
        f.ApplyBlock(Blk(3, lapseMtp, Tx1(1, 10, B.RenewAllSafe(2))));
        Check(!f.Names.ContainsKey("n0"), "TV-7", "n0 lapses in the pre-block phase");
        Check(Mut(f, 1) == 3, "TV-7", "the lapse bumps Id1's set-mutation height to the connecting height (3)");
        Check(f.Names.ContainsKey("n1") && f.Names["n1"].LeaseExpiry == n1Before,
            "TV-7", "the stale-anchored RENEW (anchor=2 < mut=3) drops; n1's lease is unchanged");
    }

    // TV-8: a RELEASE-all selectively SKIPS a LISTED (locked) name instead of freeing it.
    private static void TV8()
    {
        var f = ClaimThree(1);
        // list n1 (lock it). price 3 ≥ 3·DUST_FLOOR; window 0 → RESERVE_WINDOW; 365-day tail covers it.
        f.ApplyBlock(Blk(3, T0 + 600, Tx1(1, 0, B.Sell(3, 0, "n1"))));
        // RELEASE all three (flags 0x07), anchor = 2 (SELL is not a set-mutation).
        f.ApplyBlock(Blk(4, T0 + 900, Tx1(1, 0, B.Release(2, new byte[] { 0x07 }))));
        Check(!f.Names.ContainsKey("n0") && !f.Names.ContainsKey("n2"), "TV-8", "RELEASE frees the unlocked n0,n2");
        Check(f.Names.ContainsKey("n1") && f.Names["n1"].St == K.ST_LISTED, "TV-8", "RELEASE skips the locked (LISTED) n1, not freeing it");
    }

    // M9: TRADE is attributed to its named parties vin[idxA]/vin[idxB], NOT the tx's
    // acting identity, so a TRADE whose vin[0] is ⊥ still settles.
    private static void M9()
    {
        var f = new Fold();
        f.ApplyBlock(Blk(1, T0,
            CommitTx(1, 0xA0, "alpha"),
            CommitTx(2, 0xB0, "beta")));
        f.ApplyBlock(Blk(2, T0 + 300,
            ClaimTx(1, 365, 0xA0, "alpha"),
            ClaimTx(2, 365, 0xB0, "beta")));
        // inputs: vin0 = ⊥ (failed §4), vin1 = A(Id1), vin2 = B(Id2). TRADE idxA=1, idxB=2.
        var tradeTx = Tx(new[] { BottomIn(), B.In(1), B.In(2) },
                         new[] { Out.Carrier(B.Trade(1, 2, "alpha", "beta"), 0) });
        f.ApplyBlock(Blk(3, T0 + 100_000, tradeTx));
        Check(OwnedBy(f, "alpha", 2) && OwnedBy(f, "beta", 1),
            "M9", "TRADE settles via named parties even when vin[0] acting identity is ⊥");
    }

    // H8: a commit consumed by a successful claim is NOT removed at claim time; it
    // lingers in the commits table until the COMMIT_EXPIRY pre-block prune.
    private static void H8()
    {
        var f = new Fold();
        f.ApplyBlock(Blk(1, T0, CommitTx(1, 0x11, "alpha")));
        f.ApplyBlock(Blk(2, T0 + 300, ClaimTx(1, 30, 0x11, "alpha")));
        Check(OwnedBy(f, "alpha", 1), "H8", "claim succeeds");
        Check(f.Commits.Count == 1, "H8", "the used commit lingers in the table after the claim");
        f.ApplyBlock(Blk(3, T0 + K.COMMIT_EXPIRY + 1)); // advance past commit_time+COMMIT_EXPIRY
        Check(f.Commits.Count == 0, "H8", "the lingering commit is pruned once MTP passes commit_time+COMMIT_EXPIRY");
        Check(OwnedBy(f, "alpha", 1), "H8", "pruning the commit does not affect the already-minted name");
    }

    // H3: a set-mutation (last_set_mutation_height) row is never pruned — it persists
    // even after the owner's live name set falls to empty.
    private static void H3()
    {
        var f = new Fold();
        f.ApplyBlock(Blk(1, T0, CommitTx(1, 0x11, "solo")));
        f.ApplyBlock(Blk(2, T0 + 300, ClaimTx(1, 1, 0x11, "solo"))); // 1-day lease
        f.ApplyBlock(Blk(3, (T0 + 300) + 1 * K.BILLING_UNIT));        // lapse it
        Check(!f.Names.ContainsKey("solo"), "H3", "Id1's only name lapses → Id1 owns nothing");
        Check(Mut(f, 1) == 3, "H3", "Id1's set-mutation row persists (stamped at the lapse height 3) after the set empties");
    }
}
