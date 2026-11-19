using System;
using System.Security.Cryptography;
using System.Text;

namespace Pepenet;

/// <summary>
/// §13.2 ECMH primitive vector set (`sm ecmh`). Mirrors impls/c/src/ecmh.c
/// (ecmh_cmd): hash-to-curve KATs, identity serialization, a tagged multiset sum
/// (commutativity + inverse round-trip), printed as a cross-language byte-identical
/// `combined` digest against this impl's own secp256k1. Names-only: no vote tag.
/// </summary>
public static class Ecmh
{
    // domain tags — second-preimage separation between tables (TAG_MUT keeps 0x04).
    private const byte TagName = 0x01, TagCommit = 0x02, TagMut = 0x04;
    private static readonly byte[] RecTag = { (byte)'E', (byte)'C', (byte)'M', (byte)'H', (byte)'v', (byte)'1' };

    public static int Run()
    {
        var sb = new StringBuilder();
        var comb = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        void Feed(byte[] d, int n) { comb.AppendData(d, 0, n); }
        void Feed1(byte b) => comb.AppendData(new[] { b }, 0, 1);

        // version self-doc
        sb.Append("ecmh ECMHv1\n"); Feed(RecTag, 6);

        // 1. hash-to-curve KAT — fixed preimages → (ctr, compressed even-Y point).
        var h2c = new (string label, byte[] pre)[]
        {
            ("empty", Array.Empty<byte>()),
            ("a",     Encoding.ASCII.GetBytes("a")),
            ("pepe",  Encoding.ASCII.GetBytes("pepenet")),
            ("doge",  Encoding.ASCII.GetBytes("doge")),
            ("ff32",  Fill(32, 0xFF)),
            ("z32",   new byte[32]),
        };
        foreach (var (label, pre) in h2c)
        {
            int ctr = Secp256k1.EcmhHash(pre, out byte[] pt);
            sb.Append("h2c ").Append(label).Append(" ctr=").Append(ctr).Append(" pt=").Append(Hx(pt)).Append('\n');
            Feed1((byte)ctr); Feed(pt, 33);
        }

        // 2. identity (∞) serialization
        byte[] id = Secp256k1.EcmhIdentity();
        sb.Append("identity ").Append(Hx(id)).Append('\n'); Feed(id, 33);

        // 3. tagged multiset sum — a fixed set of (tag ‖ row) records, summed two ways.
        var recs = new (byte tag, byte[] body)[]
        {
            (TagName,   Bytes(0x03, "foo")),
            (TagName,   Bytes(0x03, "bar")),
            (TagCommit, Encoding.ASCII.GetBytes("commitment-blob-32-bytes-xxxxxx")),
            (TagMut,    Encoding.ASCII.GetBytes("owner-mutation")),
        };
        byte[] fwd = Secp256k1.EcmhIdentity(), rev = Secp256k1.EcmhIdentity();
        for (int i = 0; i < recs.Length; i++)
        {
            Secp256k1.EcmhHash(RecPre(recs[i].tag, recs[i].body), out byte[] pt);
            Secp256k1.EcmhAdd(fwd, pt);
        }
        for (int i = recs.Length - 1; i >= 0; i--)
        {
            Secp256k1.EcmhHash(RecPre(recs[i].tag, recs[i].body), out byte[] pt);
            Secp256k1.EcmhAdd(rev, pt);
        }
        int commut = Eq(fwd, rev) ? 1 : 0;
        sb.Append("sum ").Append(Hx(fwd)).Append('\n');
        sb.Append("commutative ").Append(commut).Append('\n');
        Feed(fwd, 33); Feed1((byte)commut);

        // 4. inverse — remove the first record from the sum, re-add, must round-trip.
        {
            Secp256k1.EcmhHash(RecPre(recs[0].tag, recs[0].body), out byte[] pt0);
            byte[] acc = (byte[])fwd.Clone();
            byte[] npt = (byte[])pt0.Clone(); Secp256k1.EcmhNegate(npt);
            Secp256k1.EcmhAdd(acc, npt);   // remove rec[0]
            Secp256k1.EcmhAdd(acc, pt0);   // re-add rec[0]
            int roundtrip = Eq(acc, fwd) ? 1 : 0;
            sb.Append("inverse_roundtrip ").Append(roundtrip).Append('\n');
            Feed1((byte)roundtrip);
        }

        byte[] cd = comb.GetHashAndReset();
        sb.Append("combined ").Append(Hx(cd)).Append('\n');

        Console.Out.Write(sb.ToString());
        return 0;
    }

    private static byte[] RecPre(byte tag, byte[] body)
    {
        byte[] r = new byte[6 + 1 + body.Length];
        Buffer.BlockCopy(RecTag, 0, r, 0, 6);
        r[6] = tag;
        Buffer.BlockCopy(body, 0, r, 7, body.Length);
        return r;
    }

    private static byte[] Bytes(byte lead, string s)
    {
        byte[] t = Encoding.ASCII.GetBytes(s);
        byte[] r = new byte[1 + t.Length]; r[0] = lead;
        Buffer.BlockCopy(t, 0, r, 1, t.Length);
        return r;
    }
    private static byte[] Fill(int n, byte v) { byte[] r = new byte[n]; for (int i = 0; i < n; i++) r[i] = v; return r; }
    private static bool Eq(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
        return true;
    }
    private static string Hx(byte[] d) { var sb = new StringBuilder(d.Length * 2); foreach (var b in d) sb.Append(b.ToString("x2")); return sb.ToString(); }
}
