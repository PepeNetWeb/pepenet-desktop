using System;
using System.Collections.Generic;
using System.Buffers.Binary;

namespace Pepenet;

/// <summary>
/// Generator-driven invariant battery (§8/§9/§10/§11). These modes use THIS impl's
/// OWN generator + OWN prng, so their digests do NOT match the gen.c-pinned soak
/// goldens (only the 0-counts are normative). The VALUE is the generator-INDEPENDENT
/// assertions: properties' violations==0 (the fold preserves every §8 invariant),
/// meta/reorg/reorgfuzz's failures==0 (the fold is drop-closed and a pure, reorg-safe
/// function of the block sequence), and fuzz's parser_crashes==0 (the decoder/fold is
/// fail-closed over adversarial bytes). Names-only fingerprint: no votes/decors/overflow.
/// </summary>
public static class Modes
{
    // ---------------- §8 property battery ----------------
    public static int Properties(ulong seed, int count)
    {
        var blocks = OwnGenerator.RecordChain(seed, count);
        var f = new Fold();
        long violations = 0;
        var pd = new HashBuf();
        foreach (var b in blocks)
        {
            f.ApplyBlock(b);
            violations += CheckInvariants(f, b.Height, b.Mtp);
            Fingerprint(pd, f);
        }
        Console.WriteLine($"violations={violations}");
        Console.WriteLine($"property_digest={Hashing.Hex(Hashing.Sha256(pd.ToSpan()))}");
        Console.WriteLine($"state_digest={Digest.ComputeHex(f)}");
        return violations != 0 ? 1 : 0;
    }

    private static long CheckInvariants(Fold f, long height, long mtp)
    {
        long v = 0;
        foreach (var r in f.Names.Values)
        {
            // mtp < lease_expiry <= mtp + MAX_LEASE
            if (!(mtp < r.LeaseExpiry)) v++;
            if (!(r.LeaseExpiry <= mtp + K.MAX_LEASE)) v++;
            if (r.St == K.ST_LISTED || r.St == K.ST_OFFERED || r.St == K.ST_RESERVED)
            {
                if (!(r.OfferExpiry + K.REORG_BUFFER <= r.LeaseExpiry)) v++;
            }
            if (r.St == K.ST_LISTED || r.St == K.ST_RESERVED)
            {
                if (r.Price < 3UL * K.DUST_FLOOR) v++; // SELL_FLOOR = 3 * DUST_FLOOR
            }
            if (r.St == K.ST_RESERVED)
            {
                if (!(r.ReserveExpiry <= r.OfferExpiry)) v++;
                ulong legs = r.BurnLeg + r.PayLeg;
                if (r.Price < legs) v++;
                if (r.BurnLeg != DepositLeg(r.Price, K.RESERVE_BURN_BPS)) v++;
                if (r.PayLeg != DepositLeg(r.Price, K.RESERVE_PAY_BPS)) v++;
                if (r.Price - r.BurnLeg - r.PayLeg < K.DUST_FLOOR) v++;
            }
        }
        foreach (var mh in f.Muts.Values) if (mh > height) v++; // mutation height <= cur height
        return v;
    }

    // Mirrors C sm_block_fingerprint: names-only aggregates, no votes/decors/overflow.
    private static void Fingerprint(HashBuf pd, Fold f)
    {
        int nOwned = 0, nListed = 0, nOffered = 0, nReserved = 0;
        Int128 sumLease = 0, sumPrice = 0, sumLegs = 0;
        foreach (var r in f.Names.Values)
        {
            switch (r.St)
            {
                case K.ST_OWNED: nOwned++; break;
                case K.ST_LISTED: nListed++; sumPrice += (Int128)r.Price; break;
                case K.ST_OFFERED: nOffered++; sumPrice += (Int128)r.Price; break;
                case K.ST_RESERVED:
                    nReserved++;
                    sumPrice += (Int128)r.Price;
                    sumLegs += (Int128)r.BurnLeg + (Int128)r.PayLeg;
                    break;
            }
            sumLease += r.LeaseExpiry;
        }
        pd.U32((uint)f.Names.Count).U32((uint)nOwned).U32((uint)nListed).U32((uint)nOffered).U32((uint)nReserved);
        pd.U32((uint)f.Commits.Count).U32((uint)f.Muts.Count);
        pd.I128(sumLease).I128(sumPrice).I128(sumLegs);
    }

    // ---------------- §11 meta: an IGNORED action is provably inert ----------------
    public static int Meta(ulong seed, int count)
    {
        var blocks = OwnGenerator.RecordChain(seed, Math.Min(count, 20000));
        var f = new Fold();
        long failures = 0;
        foreach (var b in blocks)
        {
            f.ApplyBlock(b);
            string before = Digest.ComputeHex(f);
            f.ApplyOneTx(InertTx(), b.Height, b.Mtp, b.Rate, b.Txs.Count);
            if (Digest.ComputeHex(f) != before) failures++;
        }
        Console.WriteLine($"failures={failures}");
        Console.WriteLine($"state_digest={Digest.ComputeHex(f)}");
        return failures != 0 ? 1 : 0;
    }

    private static Tx InertTx()
    {
        // truncated CLAIM → IGNORE; unknown opcode 0x20 → IGNORE; bare UTF-8 → IGNORE;
        // overlay-band 0xD6 → IGNORE. None mutates digested state. (mirrors C build_inert_tx)
        byte[] badClaim = new byte[] { 0xFF, 0x50, 0x4E, K.OP_CLAIM, 0, 0, 0, 0 };
        byte[] unknown = new byte[] { 0xFF, 0x50, 0x4E, 0x20 };
        byte[] hello = B.Name("hello");
        byte[] overlay = new byte[] { 0xFF, 0x50, 0x4E, 0xD6, 0x00 };
        var outs = new List<Out>
        {
            Out.Carrier(badClaim, 0),
            Out.Carrier(unknown, 0),
            Out.Carrier(hello, 1),
            Out.Carrier(overlay, 0),
        };
        return new Tx
        {
            Inputs = new List<Input> { new Input { H160 = OwnGenerator.Identity(0), Type = K.TYPE_P2PKH, SighashAll = true } },
            Outputs = outs,
        };
    }

    // ---------------- §10 reorg confluence ----------------
    public static int Reorg(ulong seed, int count)
    {
        var blocks = OwnGenerator.RecordChain(seed, Math.Min(count, 20000));
        int n = blocks.Count, J = n / 2;
        long failures = 0;

        string dFull = FoldDigest(blocks, 0, n);
        // 1. replay: a second full fold reproduces D_full.
        if (FoldDigest(blocks, 0, n) != dFull) failures++;
        // 2. resume: fold [0,J) -> S_fork, continue [J,n) == D_full.
        var f = new Fold();
        for (int idx = 0; idx < J; idx++) f.ApplyBlock(blocks[idx]);
        string sFork = Digest.ComputeHex(f);
        for (int idx = J; idx < n; idx++) f.ApplyBlock(blocks[idx]);
        if (Digest.ComputeHex(f) != dFull) failures++;
        // 3. clear-rebuild: clear(), re-fold [0,J) == S_fork.
        f.Clear();
        for (int idx = 0; idx < J; idx++) f.ApplyBlock(blocks[idx]);
        if (Digest.ComputeHex(f) != sFork) failures++;
        // 4. fork-and-return: divergent branch = canonical tail with each block's txs reversed.
        var fa = new Fold();
        for (int idx = 0; idx < J; idx++) fa.ApplyBlock(blocks[idx]);
        for (int idx = J; idx < n; idx++) fa.ApplyBlock(ReverseTxs(blocks[idx]));
        string dAlt = Digest.ComputeHex(fa);
        fa.Clear();
        for (int idx = 0; idx < J; idx++) fa.ApplyBlock(blocks[idx]);
        if (Digest.ComputeHex(fa) != sFork) failures++;
        for (int idx = J; idx < n; idx++) fa.ApplyBlock(blocks[idx]);
        if (Digest.ComputeHex(fa) != dFull) failures++;

        byte[] rd = B.Concat(HexDec(dFull), HexDec(sFork), HexDec(dAlt));
        Console.WriteLine($"blocks={n} fork={J} checks=6 failures={failures}");
        Console.WriteLine($"D_full={dFull}");
        Console.WriteLine($"S_fork={sFork}");
        Console.WriteLine($"D_alt={dAlt}");
        Console.WriteLine($"reorg_digest={Hashing.Hex(Hashing.Sha256(rd))}");
        return failures != 0 ? 1 : 0;
    }

    private static string FoldDigest(List<Block> blocks, int lo, int hi)
    {
        var f = new Fold();
        for (int i = lo; i < hi; i++) f.ApplyBlock(blocks[i]);
        return Digest.ComputeHex(f);
    }

    private static Block ReverseTxs(Block b)
    {
        var r = new List<Tx>(b.Txs);
        r.Reverse();
        return new Block { Height = b.Height, Mtp = b.Mtp, Rate = b.Rate, Txs = r };
    }

    // ---------------- §9 differential fuzz: crash-safety / fail-closed robustness ----------------
    public static int Fuzz(ulong seed, int count)
    {
        var rng = new SplitMix64(seed);
        var f = new Fold();
        var inBuf = new HashBuf();
        long ts = OwnGenerator.BASE_TS, height = 0;
        int txCount = 0, crashes = 0;
        while (txCount < count)
        {
            long tsStep = 300 + (long)rng.Bounded(600); ts += tsStep;
            ulong rate = 28UL * (1UL + rng.Bounded(4));
            int nTxs = 1 + rng.Bnd(8);
            var txs = new List<Tx>();
            for (int ti = 0; ti < nTxs && txCount < count; ti++)
            {
                int nIn = 1 + rng.Bnd(4);
                var ins = new List<Input>();
                for (int k = 0; k < nIn; k++)
                    ins.Add(new Input
                    {
                        H160 = OwnGenerator.Identity(rng.Bnd(OwnGenerator.N_IDS)),
                        Type = rng.Bnd(4) == 3 ? K.TYPE_P2SH : K.TYPE_P2PKH,
                        SighashAll = rng.Bnd(8) != 0,
                    });
                int nOut = 1 + rng.Bnd(4);
                var outs = new List<Out>();
                for (int o = 0; o < nOut; o++)
                {
                    ulong val = rng.Bnd(3) switch
                    {
                        0 => 0UL,
                        1 => ulong.MaxValue - rng.Bounded(1000),
                        _ => 1UL + rng.Bounded(1000),
                    };
                    Out outp;
                    if (rng.Bnd(4) == 0)
                        outp = Out.Spend(OwnGenerator.Identity(rng.Bnd(OwnGenerator.N_IDS)), (byte)rng.Bnd(2), val);
                    else
                        outp = Out.Carrier(FuzzPayload(rng), val);
                    outs.Add(outp);
                    inBuf.U8((byte)o).U64(val);
                    if (outp.Kind == OutKind.Carrier) inBuf.U32((uint)outp.Payload.Length).Bytes(outp.Payload);
                }
                txs.Add(new Tx { Inputs = ins, Outputs = outs });
                txCount++;
            }
            var b = new Block { Height = height, Mtp = ts, Rate = rate, Txs = txs };
            try { f.ApplyBlock(b); }
            catch (Exception) { crashes++; }
            height++;
        }
        Console.WriteLine($"input_digest={Hashing.Hex(Hashing.Sha256(inBuf.ToSpan()))}");
        Console.WriteLine($"state_digest={Digest.ComputeHex(f)}");
        Console.WriteLine($"parser_crashes={crashes}");
        return crashes != 0 ? 1 : 0;
    }

    private static byte[] FuzzPayload(SplitMix64 rng)
    {
        if (rng.Bnd(10) < 4) // dumb-random bytes
        {
            int len = rng.Bnd(81);
            byte[] p = new byte[len];
            for (int i = 0; i < len; i++) p[i] = (byte)rng.Bnd(256);
            if (rng.Bnd(3) == 0 && len >= 4) { p[0] = 0xFF; p[1] = 0x50; p[2] = 0x4E; p[3] = (byte)(1 + rng.Bnd(15)); } // 0x01..0x0F
            return p;
        }
        // grammar-aware: build a prefixed action-shaped payload, then maybe corrupt.
        byte[] payload = GrammarPayload(rng);
        switch (rng.Bnd(6))
        {
            case 2: if (payload.Length > 0) payload = payload[..^1]; break;                          // truncate
            case 3: if (payload.Length > 0) payload[rng.Bnd(payload.Length)] ^= (byte)(1 << rng.Bnd(8)); break; // flip
            case 4: payload = B.Concat(payload, new byte[] { (byte)rng.Bnd(256) }); break;            // extend
            default: break;
        }
        return payload;
    }

    private static byte[] GrammarPayload(SplitMix64 rng)
    {
        int op = 1 + rng.Bnd(15); // 0x01..0x0F
        int bodyLen = op switch
        {
            K.OP_COMMIT => 32,
            K.OP_CLAIM => 33 + rng.Bnd(32),
            K.OP_RENEW_NAME or K.OP_RELEASE_NAME => 1 + rng.Bnd(32),
            K.OP_TRANSFER_NAME => 21 + rng.Bnd(31),
            K.OP_RENEW => new[] { 0, 5, 6 + rng.Bnd(71) }[rng.Bnd(3)],
            K.OP_TRANSFER => rng.Bnd(2) == 0 ? 20 : 26 + rng.Bnd(51),
            K.OP_SELL => 13 + rng.Bnd(32),
            K.OP_RESERVE or K.OP_SETTLE or K.OP_PAY => 1 + rng.Bnd(32),
            K.OP_RELEASE => 6 + rng.Bnd(71),
            K.OP_SELL_TO => 29 + rng.Bnd(32),
            K.OP_AS => 1,
            K.OP_TRADE => 5 + rng.Bnd(30),
            _ => rng.Bnd(77),
        };
        byte[] p = new byte[4 + bodyLen];
        p[0] = 0xFF; p[1] = 0x50; p[2] = 0x4E; p[3] = (byte)op;
        for (int i = 4; i < p.Length; i++) p[i] = (byte)rng.Bnd(256);
        return p;
    }

    // ---------------- §11 reorgfuzz: K=64 fork/divergence trials ----------------
    public static int Reorgfuzz(ulong seed, int count)
    {
        var blocks = OwnGenerator.RecordChain(seed, Math.Min(count, 20000));
        int n = blocks.Count;
        string dFull = FoldDigest(blocks, 0, n);
        var tr = new SplitMix64(seed ^ 0x5245464B5A475F31UL);
        var altStream = new HashBuf();
        long failures = 0;
        for (int t = 0; t < 64; t++)
        {
            int J = (int)tr.Bounded((ulong)(n + 1));
            int kind = tr.Bnd(3);
            // divergent branch -> D_alt
            var sd = new Fold();
            for (int i = 0; i < J; i++) sd.ApplyBlock(blocks[i]);
            foreach (var b in DivergentTail(blocks, J, n, kind)) sd.ApplyBlock(b);
            altStream.Bytes(HexDec(Digest.ComputeHex(sd)));
            // assert: clear-rebuild to J reproduces fold[0,J); canonical replay reproduces D_full.
            string forkJ = FoldDigest(blocks, 0, J);
            var sc = new Fold();
            for (int i = 0; i < J; i++) sc.ApplyBlock(blocks[i]);
            if (Digest.ComputeHex(sc) != forkJ) failures++;
            for (int i = J; i < n; i++) sc.ApplyBlock(blocks[i]);
            if (Digest.ComputeHex(sc) != dFull) failures++;
        }
        altStream.Bytes(HexDec(dFull));
        Console.WriteLine($"blocks={n} trials=64 failures={failures}");
        Console.WriteLine($"reorgfuzz_digest={Hashing.Hex(Hashing.Sha256(altStream.ToSpan()))}");
        return failures != 0 ? 1 : 0;
    }

    private static List<Block> DivergentTail(List<Block> blocks, int J, int n, int kind)
    {
        var outl = new List<Block>();
        switch (kind)
        {
            case 0: for (int i = J; i < n; i++) outl.Add(ReverseTxs(blocks[i])); break;          // reversed tail
            case 1: for (int i = J; i < n; i += 2) outl.Add(blocks[i]); break;                    // every other block
            default: for (int i = J; i < n; i++) { outl.Add(blocks[i]); outl.Add(blocks[i]); } break; // tail folded twice
        }
        return outl;
    }

    // ---------------- helpers ----------------
    private static ulong DepositLeg(ulong price, ulong bps)
    {
        UInt128 prod = (UInt128)price * (UInt128)bps;
        ulong floored = (ulong)(prod / 10000);
        return Math.Max(K.DUST_FLOOR, floored);
    }

    private static byte[] HexDec(string hex)
    {
        byte[] b = new byte[hex.Length / 2];
        for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return b;
    }

    /// <summary>Growable byte buffer with LE integer appenders, for streaming fingerprint/input hashes.</summary>
    private sealed class HashBuf
    {
        private byte[] _b = new byte[256];
        private int _len;
        private void Ensure(int n) { if (_len + n > _b.Length) Array.Resize(ref _b, Math.Max(_b.Length * 2, _len + n)); }
        public HashBuf U8(byte v) { Ensure(1); _b[_len++] = v; return this; }
        public HashBuf Bytes(byte[] v) { Ensure(v.Length); Buffer.BlockCopy(v, 0, _b, _len, v.Length); _len += v.Length; return this; }
        public HashBuf U32(uint v) { Ensure(4); BinaryPrimitives.WriteUInt32LittleEndian(_b.AsSpan(_len, 4), v); _len += 4; return this; }
        public HashBuf U64(ulong v) { Ensure(8); BinaryPrimitives.WriteUInt64LittleEndian(_b.AsSpan(_len, 8), v); _len += 8; return this; }
        public HashBuf I128(Int128 v)
        {
            UInt128 u = unchecked((UInt128)v);
            U64((ulong)(u & ulong.MaxValue));
            U64((ulong)(u >> 64));
            return this;
        }
        public ReadOnlySpan<byte> ToSpan() => _b.AsSpan(0, _len);
    }
}
