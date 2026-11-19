using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Pepenet;

/// <summary>
/// §4 Strategy B — the pinned ECDSA curve-vector set (`sm attrib-curve`).
/// Mirrors impls/c/src/attrib_curve.c (attrib_cmd_curve) + the e2e in attrib.c
/// (attrib_real_endtoend). Prints byte-identical output to the C reference:
/// pinned P/N/N_HALF, on-curve edges, RFC-6979 signers + verify-boundary battery,
/// tiny-key KAT, PRIMARY `combined` digest, then 3 end-to-end txs + `combined_e2e`.
/// </summary>
public static class AttribCurve
{
    private static readonly byte[] CV_P     = Hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    private static readonly byte[] CV_N     = Hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    private static readonly byte[] CV_NHALF = Hex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0");
    private static readonly byte[] CV_GX    = Hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    private static readonly byte[] CV_GY    = Hex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");

    public static int Run()
    {
        var sb = new StringBuilder();
        var comb = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        void Feed(byte[] d, int n) { comb.AppendData(d, 0, n); }
        void Feed1(byte b) => comb.AppendData(new[] { b }, 0, 1);

        // ── 1. pinned constants ──────────────────────────────────────────────
        sb.Append("p ").Append(Hx(CV_P)).Append('\n');         Feed(CV_P, 32);
        sb.Append("n ").Append(Hx(CV_N)).Append('\n');         Feed(CV_N, 32);
        sb.Append("nhalf ").Append(Hx(CV_NHALF)).Append('\n'); Feed(CV_NHALF, 32);

        // ── 2. on-curve membership at the edges ──────────────────────────────
        var oc = new List<(string name, byte[] key)>();
        { byte[] b = new byte[65]; b[0] = 0x04; Copy(b, 1, CV_GX); Copy(b, 33, CV_GY); oc.Add(("oc_G_uncomp", b)); }
        { byte[] b = new byte[33]; b[0] = 0x02; Copy(b, 1, CV_GX); oc.Add(("oc_G_comp02", b)); }
        { byte[] b = new byte[33]; b[0] = 0x03; Copy(b, 1, CV_GX); oc.Add(("oc_G_comp03", b)); }
        { byte[] b = new byte[65]; b[0] = 0x04; Copy(b, 1, CV_GX); Copy(b, 33, CV_GY); b[64] ^= 0x01; oc.Add(("oc_G_badY", b)); }
        { byte[] b = new byte[33]; b[0] = 0x02; oc.Add(("oc_X0", b)); }                       // X=0
        { byte[] b = new byte[33]; b[0] = 0x02; b[32] = 1; oc.Add(("oc_X1", b)); }            // X=1
        { byte[] b = new byte[65]; b[0] = 0x04; Copy(b, 1, CV_P); Copy(b, 33, CV_GY); oc.Add(("oc_Xeqp", b)); }
        { byte[] b = new byte[33]; b[0] = 0x02; Copy(b, 1, CV_P); oc.Add(("oc_comp_Xeqp", b)); }
        { byte[] b = new byte[33]; b[0] = 0x05; Copy(b, 1, CV_GX); oc.Add(("oc_badprefix", b)); }
        foreach (var (name, key) in oc)
        {
            int v = Secp256k1.OnCurve(key) ? 1 : 0;
            sb.Append(name).Append(' ').Append(v).Append('\n');
            Feed1((byte)v); Feed(key, key.Length);
        }

        // ── 3 & 4. RFC-6979 deterministic sign + ECDSA verify at the boundaries ─
        for (int i = 0; i < 4; i++)
        {
            byte[] priv = new byte[32];
            priv[28] = 0xC0; priv[29] = 0xFF; priv[30] = 0xEE; priv[31] = (byte)(0x10 + i);
            if (!Secp256k1.Pubkey(priv, out byte[] pub)) { sb.Append("sig").Append(i).Append(" PUBFAIL\n"); continue; }
            byte[] m = Encoding.ASCII.GetBytes("strategy-b curve vector " + i);
            byte[] h = Hashing.Sha256(m);
            if (!Secp256k1.EcdsaSign(priv, h, out byte[] r, out byte[] s)) { sb.Append("sig").Append(i).Append(" SIGNFAIL\n"); continue; }
            byte[] der = DerSig(r, s);
            sb.Append("sig").Append(i).Append(" pub=").Append(Hx(pub))
              .Append(" r=").Append(Hx(r))
              .Append(" s=").Append(Hx(s))
              .Append(" der=").Append(Hx(der)).Append('\n');
            Feed(pub, 33); Feed(r, 32); Feed(s, 32); Feed(der, der.Length);

            // verify boundary battery
            byte[] zero = new byte[32];
            byte[] hbad = (byte[])h.Clone(); hbad[0] ^= 0x01;
            byte[] hiS = new byte[32];                          // high-S = n - s (byte subtraction)
            { int borrow = 0; for (int k = 31; k >= 0; k--) { int d = CV_N[k] - s[k] - borrow; if (d < 0) { d += 256; borrow = 1; } else borrow = 0; hiS[k] = (byte)d; } }
            byte[] wrongpub = (byte[])pub.Clone(); wrongpub[0] ^= 0x01;
            var vt = new (string nm, byte[] hh, byte[] rr, byte[] ss, byte[] pk)[]
            {
                ("valid",   h,    r,    s,    pub),
                ("tamper",  hbad, r,    s,    pub),
                ("r0",      h,    zero, s,    pub),
                ("s0",      h,    r,    zero, pub),
                ("rN",      h,    CV_N, s,    pub),
                ("sN",      h,    r,    CV_N, pub),
                ("highS",   h,    r,    hiS,  pub),
                ("wrongpk", h,    r,    s,    wrongpub),
            };
            sb.Append("ver").Append(i);
            foreach (var t in vt)
            {
                int v = Secp256k1.EcdsaVerify(t.hh, t.rr, t.ss, t.pk) ? 1 : 0;
                sb.Append(' ').Append(t.nm).Append('=').Append(v);
                Feed1((byte)v);
            }
            sb.Append('\n');
        }

        // ── 5. tiny-key KAT: priv=1 ⇒ pub=G ; priv=2 ⇒ pub=2G ────────────────
        { byte[] p1 = new byte[32]; p1[31] = 1; Secp256k1.Pubkey(p1, out byte[] pk1); sb.Append("priv1_pub=").Append(Hx(pk1)).Append('\n'); Feed(pk1, 33); }
        { byte[] p2 = new byte[32]; p2[31] = 2; Secp256k1.Pubkey(p2, out byte[] pk2); sb.Append("priv2_pub=").Append(Hx(pk2)).Append('\n'); Feed(pk2, 33); }

        byte[] cd = comb.GetHashAndReset();
        sb.Append("combined ").Append(Hx(cd)).Append('\n');

        // ── 6. end-to-end (attrib_real_endtoend) ─────────────────────────────
        var e2e = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        EndToEnd(sb, e2e);
        byte[] ed = e2e.GetHashAndReset();
        sb.Append("combined_e2e ").Append(Hx(ed)).Append('\n');

        Console.Out.Write(sb.ToString());
        return 0;
    }

    // mirror C der_int/der_sig (canonical strict-DER ‖ SIGHASH_ALL).
    private static byte[] DerInt(byte[] v)
    {
        int i = 0; while (i < 31 && v[i] == 0) i++;
        int len = 32 - i; int pad = (v[i] & 0x80) != 0 ? 1 : 0;
        byte[] outp = new byte[2 + pad + len];
        int n = 0;
        outp[n++] = 0x02; outp[n++] = (byte)(len + pad);
        if (pad == 1) outp[n++] = 0x00;
        Buffer.BlockCopy(v, i, outp, n, len);
        return outp;
    }
    private static byte[] DerSig(byte[] r, byte[] s)
    {
        byte[] ri = DerInt(r), si = DerInt(s);
        int bl = ri.Length + si.Length;
        byte[] outp = new byte[2 + bl + 1];
        outp[0] = 0x30; outp[1] = (byte)bl;
        Buffer.BlockCopy(ri, 0, outp, 2, ri.Length);
        Buffer.BlockCopy(si, 0, outp, 2 + ri.Length, si.Length);
        outp[2 + bl] = 0x01; // SIGHASH_ALL
        return outp;
    }

    // ── end-to-end: sign the actual legacy sighash, attribute() with real curve ──
    private static void EndToEnd(StringBuilder sb, IncrementalHash comb)
    {
        bool prev = Attribution.RealCurve;
        Attribution.RealCurve = true;
        try
        {
            void Emit(string name, RawTx tx)
            {
                AttribResult res = Attribution.Attribute(tx, 0);
                sb.Append(name).Append(' ').Append(res.Status).Append(':').Append(Hx(res.Identity)).Append('\n');
                comb.AppendData(new[] { (byte)res.Status }, 0, 1);
                comb.AppendData(res.Sighash, 0, 32);
                comb.AppendData(res.Identity, 0, 20);
            }

            // A. P2PKH, correctly signed ⇒ FOUND (priv = 0x2A)
            {
                byte[] priv = new byte[32]; priv[31] = 0x2A;
                Secp256k1.Pubkey(priv, out byte[] pub);
                byte[] h160 = Hashing.Hash160(pub);
                byte[] sc = Attribution.P2pkhScriptCode(h160);
                byte[] sh = SkeletonSighash(sc);
                Secp256k1.EcdsaSign(priv, sh, out byte[] r, out byte[] s);
                byte[] der = DerSig(r, s);
                byte[] ss = Concat(EmitPush(der), EmitPush(pub));
                Emit("e2e_p2pkh_valid", SkeletonTx(ss));
            }
            // B. P2PKH, signed by the WRONG key ⇒ verify-drop (status 2)
            {
                byte[] priv = new byte[32]; priv[31] = 0x2A;
                byte[] wrong = new byte[32]; wrong[31] = 0x2B;
                Secp256k1.Pubkey(priv, out byte[] pub);
                byte[] h160 = Hashing.Hash160(pub);
                byte[] sc = Attribution.P2pkhScriptCode(h160);
                byte[] sh = SkeletonSighash(sc);
                Secp256k1.EcdsaSign(wrong, sh, out byte[] r, out byte[] s);
                byte[] der = DerSig(r, s);
                byte[] ss = Concat(EmitPush(der), EmitPush(pub));
                Emit("e2e_p2pkh_wrongkey", SkeletonTx(ss));
            }
            // C. 2-of-2 P2SH multisig, two correct in-order sigs ⇒ FOUND (privs 0x50,0x51)
            {
                byte[][] priv = new byte[2][]; byte[][] pub = new byte[2][];
                for (int i = 0; i < 2; i++) { priv[i] = new byte[32]; priv[i][31] = (byte)(0x50 + i); Secp256k1.Pubkey(priv[i], out pub[i]); }
                // redeem: OP_2 <k0><k1> OP_2 OP_CHECKMULTISIG
                var rs = new List<byte> { 0x52 };
                for (int i = 0; i < 2; i++) { rs.Add(0x21); rs.AddRange(pub[i]); }
                rs.Add(0x52); rs.Add(0xAE);
                byte[] redeem = rs.ToArray();
                byte[] sh = SkeletonSighash(redeem);
                var ss = new List<byte> { 0x00 };                // NULLDUMMY
                for (int i = 0; i < 2; i++)
                {
                    Secp256k1.EcdsaSign(priv[i], sh, out byte[] r, out byte[] s);
                    ss.AddRange(EmitPush(DerSig(r, s)));
                }
                ss.AddRange(EmitPush(redeem));
                Emit("e2e_multisig_valid", SkeletonTx(ss.ToArray()));
            }
        }
        finally { Attribution.RealCurve = prev; }
    }

    // shared tx skeleton: 1 input (outpoint 0x11.., seq FFFFFFFF), 1 output (value 100000,
    // scriptPubKey = OP_RETURN), version 1, locktime 0.
    private static RawTx SkeletonTx(byte[] scriptSig)
    {
        byte[] prev = new byte[32]; for (int i = 0; i < 32; i++) prev[i] = 0x11;
        return new RawTx
        {
            Version = 1,
            Inputs = { new RawInput { PrevHash = prev, PrevN = 0x11111111, ScriptSig = scriptSig, Sequence = 0xFFFFFFFF } },
            Outputs = { new RawOutput { Value = 100000, ScriptPubKey = new byte[] { 0x6a } } },
            Locktime = 0,
        };
    }
    private static byte[] SkeletonSighash(byte[] scriptCode)
    {
        // the legacy sighash computed by attribute() over the same skeleton (no scriptSig sigs to FaD here).
        return Attribution.LegacySighash(SkeletonTx(Array.Empty<byte>()), 0, scriptCode, Array.Empty<byte[]>());
    }

    private static byte[] EmitPush(byte[] data)
    {
        if (data.Length < 0x4C)
        {
            byte[] r = new byte[1 + data.Length]; r[0] = (byte)data.Length; Buffer.BlockCopy(data, 0, r, 1, data.Length); return r;
        }
        byte[] r2 = new byte[2 + data.Length]; r2[0] = 0x4C; r2[1] = (byte)data.Length; Buffer.BlockCopy(data, 0, r2, 2, data.Length); return r2;
    }

    // ── small helpers ────────────────────────────────────────────────────────
    private static void Copy(byte[] dst, int off, byte[] src) => Buffer.BlockCopy(src, 0, dst, off, src.Length);
    private static byte[] Concat(params byte[][] parts)
    {
        int len = 0; foreach (var p in parts) len += p.Length;
        byte[] r = new byte[len]; int o = 0; foreach (var p in parts) { Buffer.BlockCopy(p, 0, r, o, p.Length); o += p.Length; } return r;
    }
    private static byte[] Hex(string s) { byte[] r = new byte[s.Length / 2]; for (int i = 0; i < r.Length; i++) r[i] = Convert.ToByte(s.Substring(i * 2, 2), 16); return r; }
    private static string Hx(byte[] d) { var sb = new StringBuilder(d.Length * 2); foreach (var b in d) sb.Append(b.ToString("x2")); return sb.ToString(); }
}
