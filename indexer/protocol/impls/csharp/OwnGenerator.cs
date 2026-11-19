using System;
using System.Collections.Generic;
using System.Buffers.Binary;

namespace Pepenet;

/// <summary>
/// THIS implementation's OWN generator — internally consistent and deterministic,
/// but deliberately NOT the reference's pinned draw-order (SPEC §5), which depends
/// on the forbidden impls/c. It exists only to drive the fold richly and produce a
/// non-trivial state for the generator-INDEPENDENT property/reorg/meta assertions
/// (violations==0, failures==0). Its (seed,count)→digest values are this impl's own
/// regression baseline, not comparable to the reference.
///
/// Generation is SEPARATED from folding: <see cref="RecordChain"/> RECORDS a
/// re-foldable List&lt;Block&gt; (it folds an internal scratch state only to decide
/// which ops are currently valid). The recorded list can be folded multiple times,
/// partially, or forked — which is exactly what reorg/reorgfuzz need.
/// Names-only: no POST/VOTE/DECORATE.
/// </summary>
public static class OwnGenerator
{
    public const int N_IDS = 16;
    public const int NAME_POOL = 400;
    public const long BASE_TS = 1_700_000_000L;

    // op weights (names/market only; mirrors C gen.c WEIGHT[]):
    // 0=COMMIT 1=CLAIM 2=RENEW 3=TRANSFER 4=SELL 5=RESERVE 6=SETTLE 7=RELEASE 8=SELL_TO 9=PAY 10=TRADE
    private static readonly int[] WEIGHTS = { 14, 13, 5, 5, 8, 7, 7, 3, 6, 5, 4 };
    private static readonly int WSUM;
    static OwnGenerator() { int s = 0; foreach (var w in WEIGHTS) s += w; WSUM = s; }

    // ---- identity / name helpers ----
    public static byte[] Identity(int i) { var h = new byte[20]; h[0] = (byte)i; h[19] = (byte)i; return h; }
    public static byte IdType(int i) => (i % 4 == 3) ? K.TYPE_P2SH : K.TYPE_P2PKH;
    public static byte[] NameOf(int i) => B.Name("n" + Base36(i));
    public static byte[] SaltOf(long k) { var s = new byte[32]; for (int i = 0; i < 8; i++) s[i] = (byte)(k >> (8 * i)); s[31] = 0xA5; return s; }

    private sealed class Pending { public int IdIdx; public byte[] Name = Array.Empty<byte>(); public byte[] Salt = Array.Empty<byte>(); public long CommitHeight; public long CommitTime; }

    /// <summary>Existing entrypoint: record the chain then fold it, returning the Fold.</summary>
    public static Fold Run(ulong seed, int count)
    {
        var blocks = RecordChain(seed, count);
        var f = new Fold();
        f.ApplyBlocks(blocks);
        return f;
    }

    /// <summary>Record a re-foldable chain. A scratch Fold is folded inline ONLY to gate
    /// op validity; the returned list is independent and can be re-folded freely.</summary>
    public static List<Block> RecordChain(ulong seed, int count)
    {
        var rng = new SplitMix64(seed);
        var scratch = new Fold();
        var blocks = new List<Block>();
        var ready = new List<Pending>();
        long ts = BASE_TS, saltCtr = 1;
        long height = 0;
        int txCount = 0;

        while (txCount < count)
        {
            long tsStep = 300 + (long)rng.Bounded(600); ts += tsStep;
            ulong rate = 28UL * (1UL + rng.Bounded(4));
            long mtp = ts; // monotonic; the abstract SM takes MTP as a per-block given
            int nTxs = 1 + rng.Bnd(8);
            var txs = new List<Tx>();
            for (int ti = 0; ti < nTxs && txCount < count; ti++)
            {
                Tx tx = BuildTx(rng, scratch, height, mtp, rate, ready, saltCtr);
                saltCtr += 4;
                txs.Add(tx);
                txCount++;
            }
            var b = new Block { Height = height, Mtp = mtp, Rate = rate, Txs = txs };
            scratch.ApplyBlock(b);
            blocks.Add(b);
            height++;
        }
        return blocks;
    }

    private static int PickOp(SplitMix64 rng)
    {
        int x = rng.Bnd(WSUM), acc = 0;
        for (int i = 0; i < WEIGHTS.Length; i++) { acc += WEIGHTS[i]; if (x < acc) return i; }
        return 0;
    }

    private static Tx OneIn(int i, params Out[] outs)
        => new() { Inputs = new List<Input> { new Input { H160 = Identity(i), Type = IdType(i), SighashAll = true } }, Outputs = new List<Out>(outs) };

    // names in scratch by (owner, requiredState); owner==null = any, reqSt<0 = any state.
    private static List<string> NamesWhere(Fold st, byte[]? owner, int reqSt)
    {
        var r = new List<string>();
        foreach (var kv in st.Names)
        {
            var row = kv.Value;
            if (owner != null && !SequenceEq(row.Owner, owner)) continue;
            if (reqSt >= 0 && row.St != reqSt) continue;
            r.Add(kv.Key);
        }
        return r;
    }

    private static List<string> OwnedSetSorted(Fold st, byte[] owner)
    {
        var rows = new List<NameRow>();
        foreach (var row in st.Names.Values) if (row.St == K.ST_OWNED && SequenceEq(row.Owner, owner)) rows.Add(row);
        rows.Sort((a, b) => ByteArrayComparer.Instance.Compare(a.Name, b.Name));
        var r = new List<string>();
        foreach (var row in rows) r.Add(Fold.NameKey(row.Name));
        return r;
    }

    private static int IdxOf(byte[] id) { for (int k = 0; k < N_IDS; k++) if (SequenceEq(Identity(k), id)) return k; return 0; }

    private static long LastMut(Fold st, byte[] owner)
        => st.Muts.TryGetValue(Hashing.Hex(owner), out var m) ? m : long.MinValue;

    private static Tx BuildTx(SplitMix64 rng, Fold st, long height, long mtp, ulong rate, List<Pending> ready, long saltCtr)
    {
        int op = PickOp(rng);
        int i = rng.Bnd(N_IDS);
        byte[] id = Identity(i);
        ulong days = 1UL + rng.Bounded(60);
        ulong rate28 = rate / 28;
        ulong leaseVal = rate28 * days;

        switch (op)
        {
            case 0: // COMMIT
            {
                int j = rng.Bnd(NAME_POOL); byte[] name = NameOf(j); byte[] salt = SaltOf(saltCtr);
                ready.Add(new Pending { IdIdx = i, Name = name, Salt = salt, CommitHeight = height, CommitTime = mtp });
                byte[] cmt = Hashing.Sha256(B.Concat(salt, name, id));
                return OneIn(i, Out.Carrier(B.Commit(cmt), 0));
            }
            case 1: // CLAIM a ready commit (>=1 deep, live, not yet a live name)
            {
                for (int k = 0; k < ready.Count; k++)
                {
                    var p = ready[k];
                    if (p.CommitHeight < height && mtp <= p.CommitTime + K.COMMIT_EXPIRY && !st.Names.ContainsKey(Fold.NameKey(p.Name)))
                    {
                        ready.RemoveAt(k);
                        byte[] payload = B.Payload(K.OP_CLAIM, B.Concat(p.Salt, p.Name));
                        return OneIn(p.IdIdx, Out.Carrier(payload, leaseVal));
                    }
                }
                break;
            }
            case 2: // RENEW all
            {
                var owned = NamesWhere(st, id, -1);
                if (owned.Count > 0) return OneIn(i, Out.Carrier(B.RenewAll(), leaseVal));
                break;
            }
            case 3: // TRANSFER all to a random id
            {
                var owned = NamesWhere(st, id, K.ST_OWNED);
                if (owned.Count > 0) return OneIn(i, Out.Carrier(B.TransferAll(Identity(rng.Bnd(N_IDS))), 0));
                break;
            }
            case 4: // SELL an owned name with enough lease tail
            {
                foreach (var nm in NamesWhere(st, id, K.ST_OWNED))
                {
                    var r = st.Names[nm];
                    if ((ulong)mtp + (ulong)K.RESERVE_WINDOW + (ulong)K.REORG_BUFFER <= (ulong)r.LeaseExpiry)
                    {
                        ulong price = 3UL + rng.Bounded(100000);
                        return OneIn(i, Out.Carrier(B.Sell(price, 0, nm), 0));
                    }
                }
                break;
            }
            case 5: // RESERVE a listed name (buyer != seller possible)
            {
                var listed = NamesWhere(st, null, K.ST_LISTED);
                if (listed.Count > 0)
                {
                    string nm = listed[rng.Bnd(listed.Count)]; var r = st.Names[nm];
                    int buyer = rng.Bnd(N_IDS);
                    ulong burn = DepositLeg(r.Price, K.RESERVE_BURN_BPS), payL = DepositLeg(r.Price, K.RESERVE_PAY_BPS);
                    return OneIn(buyer, Out.Carrier(B.Reserve(nm), burn), Out.Spend(r.Seller, r.SellerType, payL));
                }
                break;
            }
            case 6: // SETTLE a reserved name by its reserver
            {
                var res = NamesWhere(st, null, K.ST_RESERVED);
                if (res.Count > 0)
                {
                    string nm = res[rng.Bnd(res.Count)]; var r = st.Names[nm];
                    ulong rem = r.Price - r.BurnLeg - r.PayLeg;
                    int buyer = IdxOf(r.Buyer);
                    return OneIn(buyer, Out.Carrier(B.Settle(nm), 0), Out.Spend(r.Seller, r.SellerType, rem));
                }
                break;
            }
            case 7: // RELEASE owned names via a full-ish bitmap
            {
                var set = OwnedSetSorted(st, id);
                if (set.Count > 0)
                {
                    byte[] flags = new byte[(set.Count + 7) / 8];
                    for (int k = 0; k < flags.Length; k++) flags[k] = 0xFF;
                    long last = LastMut(st, id);
                    long anchor = last == long.MinValue ? height : Math.Max(last, height - 1);
                    if (anchor <= height) return OneIn(i, Out.Carrier(B.Release(anchor, flags), 0));
                }
                break;
            }
            case 8: // SELL_TO
            {
                foreach (var nm in NamesWhere(st, id, K.ST_OWNED))
                {
                    var r = st.Names[nm];
                    if ((ulong)mtp + (ulong)K.DIRECT_WINDOW + (ulong)K.REORG_BUFFER <= (ulong)r.LeaseExpiry)
                    {
                        ulong price = 1UL + rng.Bounded(100000);
                        return OneIn(i, Out.Carrier(B.SellTo(price, Identity(rng.Bnd(N_IDS)), nm), 0));
                    }
                }
                break;
            }
            case 9: // PAY an offered name by its named buyer
            {
                var off = NamesWhere(st, null, K.ST_OFFERED);
                if (off.Count > 0)
                {
                    string nm = off[rng.Bnd(off.Count)]; var r = st.Names[nm];
                    int buyer = IdxOf(r.Buyer);
                    return OneIn(buyer, Out.Carrier(B.Pay(nm), 0), Out.Spend(r.Seller, r.SellerType, r.Price));
                }
                break;
            }
            case 10: // TRADE two owned names between two ids
            {
                var myOwned = NamesWhere(st, id, K.ST_OWNED);
                int i2 = (i + 1 + rng.Bnd(N_IDS - 1)) % N_IDS; byte[] id2 = Identity(i2);
                var theirs = NamesWhere(st, id2, K.ST_OWNED);
                if (myOwned.Count > 0 && theirs.Count > 0)
                {
                    string a1 = myOwned[0], b1 = theirs[0];
                    if (a1 != b1)
                    {
                        byte[] payload = B.Trade(0, 1, a1, b1);
                        var ins = new List<Input>
                        {
                            new Input { H160 = id, Type = IdType(i), SighashAll = true },
                            new Input { H160 = id2, Type = IdType(i2), SighashAll = true },
                        };
                        return new Tx { Inputs = ins, Outputs = new List<Out> { Out.Carrier(payload, 0) } };
                    }
                }
                break;
            }
        }

        // COMMIT fallback (always valid).
        {
            int j = rng.Bnd(NAME_POOL); byte[] name = NameOf(j); byte[] salt = SaltOf(saltCtr + 1);
            ready.Add(new Pending { IdIdx = i, Name = name, Salt = salt, CommitHeight = height, CommitTime = mtp });
            byte[] cmt = Hashing.Sha256(B.Concat(salt, name, id));
            return OneIn(i, Out.Carrier(B.Commit(cmt), 0));
        }
    }

    private static ulong DepositLeg(ulong price, ulong bps)
    {
        UInt128 prod = (UInt128)price * (UInt128)bps;
        ulong floored = (ulong)(prod / 10000);
        return Math.Max(K.DUST_FLOOR, floored);
    }

    private static bool SequenceEq(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.SequenceEqual(b);

    public static string Base36(long v)
    {
        if (v == 0) return "0";
        const string d = "0123456789abcdefghijklmnopqrstuvwxyz";
        var sb = new System.Text.StringBuilder();
        while (v > 0) { sb.Insert(0, d[(int)(v % 36)]); v /= 36; }
        return sb.ToString();
    }
}
