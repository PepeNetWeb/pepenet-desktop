using System;
using System.Collections.Generic;
using System.Buffers.Binary;

namespace Pepenet;

// ---- raw tx model for the §4/§13 attribution surface ----

public sealed class RawInput
{
    public byte[] PrevHash = new byte[32];
    public uint PrevN;
    public byte[] ScriptSig = Array.Empty<byte>();
    public uint Sequence = 0xFFFFFFFF;
}
public sealed class RawOutput
{
    public long Value;
    public byte[] ScriptPubKey = Array.Empty<byte>();
}
public sealed class RawTx
{
    public int Version = 1;
    public List<RawInput> Inputs = new();
    public List<RawOutput> Outputs = new();
    public uint Locktime;
}

/// <summary>Attribution result for one input (SPEC-conformance §13).</summary>
public readonly struct AttribResult
{
    public readonly int Status;     // 0 classify-drop · 1 on-curve-drop · 2 verify-drop · 3 found
    public readonly byte[] Sighash; // 32 bytes (zero iff status 0)
    public readonly byte[] Identity;// 20 bytes (zero iff status 0)
    public readonly byte Type;      // TYPE_P2PKH / TYPE_P2SH (meaningful iff status ≥ 1)
    public AttribResult(int s, byte[] sh, byte[] id, byte t) { Status = s; Sighash = sh; Identity = id; Type = t; }
}

public static class Attribution
{
    // secp256k1 constants (big-endian 32-byte).
    private static readonly byte[] SECP_P = Hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    private static readonly byte[] SECP_N_HALF = Hex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0");

    // ---- curve oracle (§13). Injected pseudo-funcs by default (so attrib/attrib-scenario/
    // selftest stay byte-identical); the §4 Strategy-B real secp256k1 when RealCurve is set
    // (the attrib-curve e2e path toggles it). Mirrors C's g_real_curve. ----
    public static bool RealCurve = false;

    public static bool OnCurve(ReadOnlySpan<byte> pubkey)
    {
        if (RealCurve) return Secp256k1.OnCurve(pubkey.ToArray());
        Span<byte> pre = stackalloc byte[1 + 65];
        pre[0] = 0x4F; pubkey.CopyTo(pre.Slice(1));
        return Hashing.Sha256(pre.Slice(0, 1 + pubkey.Length))[0] != 0x00;
    }
    public static bool Verify(byte[] hash32, byte[] r32, byte[] s32, byte[] pubkey)
    {
        if (RealCurve) return Secp256k1.EcdsaVerify(hash32, r32, s32, pubkey);
        byte[] pre = new byte[1 + 32 + 32 + 32 + pubkey.Length];
        pre[0] = 0x56;
        Buffer.BlockCopy(hash32, 0, pre, 1, 32);
        Buffer.BlockCopy(r32, 0, pre, 33, 32);
        Buffer.BlockCopy(s32, 0, pre, 65, 32);
        Buffer.BlockCopy(pubkey, 0, pre, 97, pubkey.Length);
        return Hashing.Sha256(pre)[0] >= 0x20;
    }

    // ---- attribute(tx, k) ----
    public static AttribResult Attribute(RawTx tx, int k)
    {
        if (k < 0 || k >= tx.Inputs.Count) return Drop();
        byte[] ss = tx.Inputs[k].ScriptSig;

        List<(int op, int dataOff, int dataLen)>? ops = ParseScript(ss);
        if (ops == null) return Drop(); // non-minimal / malformed push

        // ---- P2PKH: exactly two data pushes [sig][pubkey] ----
        if (ops.Count == 2 && IsPush(ops[0].op) && IsPush(ops[1].op))
        {
            byte[] sig = Slice(ss, ops[0]);
            byte[] pub = Slice(ss, ops[1]);
            if (!ValidSig(sig, out byte[] r32, out byte[] s32)) return Drop();
            if (!CanonicalPubkeyEncoding(pub)) return Drop();

            byte[] identity = Hashing.Hash160(pub);
            byte[] scriptCode = P2pkhScriptCode(identity);
            byte[] sighash = LegacySighash(tx, k, scriptCode, new[] { sig });

            // on_curve gate (status 1 if off-curve — earliest curve stage; see SPEC-RATIONALE.md)
            if (!OnCurve(pub)) return new AttribResult(1, sighash, identity, K.TYPE_P2PKH);
            if (!Verify(sighash, r32, s32, pub)) return new AttribResult(2, sighash, identity, K.TYPE_P2PKH);
            return new AttribResult(3, sighash, identity, K.TYPE_P2PKH);
        }

        // ---- P2SH multisig: OP_0 [sig]×m [redeemScript] ----
        if (ops.Count >= 2 && ops[0].op == 0x00 && ops[0].dataLen == 0)
        {
            int last = ops.Count - 1;
            if (!IsPush(ops[last].op)) return Drop();
            byte[] redeem = Slice(ss, ops[last]);
            if (!ParseMultisigRedeem(redeem, out int m, out List<byte[]> keys)) return Drop();

            int sigCount = last - 1; // pushes between OP_0 and redeemScript
            if (sigCount != m) return Drop();

            var sigs = new List<byte[]>();
            var rs = new List<byte[]>();
            var ss32 = new List<byte[]>();
            for (int i = 1; i <= m; i++)
            {
                if (!IsPush(ops[i].op)) return Drop();
                byte[] sg = Slice(ss, ops[i]);
                if (!ValidSig(sg, out byte[] r, out byte[] s)) return Drop();
                sigs.Add(sg); rs.Add(r); ss32.Add(s);
            }

            byte[] identity = Hashing.Hash160(redeem);
            byte[] sighash = LegacySighash(tx, k, redeem, sigs.ToArray());

            // on_curve checked on ALL n keys up front (§4 step 4).
            foreach (var key in keys)
                if (!CanonicalPubkeyEncoding(key) || !OnCurve(key))
                    return new AttribResult(CanonicalPubkeyEncoding(key) ? 1 : 0, CanonicalPubkeyEncoding(key) ? sighash : Zero32(), CanonicalPubkeyEncoding(key) ? identity : Zero20(), K.TYPE_P2SH);

            // in-order signature scan
            int keyCursor = 0, matched = 0;
            for (int si = 0; si < m; si++)
            {
                bool ok = false;
                while (keyCursor < keys.Count)
                {
                    if (Verify(sighash, rs[si], ss32[si], keys[keyCursor])) { ok = true; keyCursor++; matched++; break; }
                    keyCursor++;
                }
                if (!ok) break;
            }
            if (matched == m) return new AttribResult(3, sighash, identity, K.TYPE_P2SH);
            return new AttribResult(2, sighash, identity, K.TYPE_P2SH);
        }

        return Drop();
    }

    private static AttribResult Drop() => new(0, Zero32(), Zero20(), 0);
    private static byte[] Zero32() => new byte[32];
    private static byte[] Zero20() => new byte[20];

    // ---- DER strict + low-S (BIP66) + SIGHASH_ALL byte ----
    public static bool ValidSig(byte[] sig, out byte[] r32, out byte[] s32)
    {
        r32 = new byte[32]; s32 = new byte[32];
        // sig = DER ‖ hashtype(1)
        if (sig.Length < 9 || sig.Length > 73) return false;
        int hashtype = sig[sig.Length - 1];
        if (hashtype != 0x01) return false;                   // Rule 3: exactly SIGHASH_ALL
        int derLen = sig.Length - 1;
        if (sig[0] != 0x30) return false;
        if (sig[1] != derLen - 2) return false;               // total length byte
        if (sig[2] != 0x02) return false;                     // R marker
        int lenR = sig[3];
        if (lenR == 0) return false;
        if (5 + lenR > derLen) return false;
        if ((sig[4] & 0x80) != 0) return false;               // R negative
        if (lenR > 1 && sig[4] == 0x00 && (sig[5] & 0x80) == 0) return false; // non-minimal pad
        int sMarkerPos = 4 + lenR;
        if (sig[sMarkerPos] != 0x02) return false;            // S marker
        int lenS = sig[sMarkerPos + 1];
        if (lenS == 0) return false;
        if (sMarkerPos + 2 + lenS != derLen) return false;    // exact length, no trailing
        int sOff = sMarkerPos + 2;
        if ((sig[sOff] & 0x80) != 0) return false;            // S negative
        if (lenS > 1 && sig[sOff] == 0x00 && (sig[sOff + 1] & 0x80) == 0) return false; // non-minimal pad

        // extract R, S as 32-byte BE
        byte[] rRaw = new byte[lenR]; Buffer.BlockCopy(sig, 4, rRaw, 0, lenR);
        byte[] sRaw = new byte[lenS]; Buffer.BlockCopy(sig, sOff, sRaw, 0, lenS);
        if (!ToBe32(rRaw, r32) || !ToBe32(sRaw, s32)) return false;

        // low-S: S ≤ N/2
        if (CompareBe(s32, SECP_N_HALF) > 0) return false;
        return true;
    }

    /// <summary>Strip a single leading 0x00 sign byte, then left-pad to 32 BE. (see SPEC-RATIONALE.md)</summary>
    private static bool ToBe32(byte[] raw, byte[] outp)
    {
        int start = 0;
        if (raw.Length == 33 && raw[0] == 0x00) start = 1;
        int len = raw.Length - start;
        if (len > 32) return false;
        for (int i = 0; i < 32; i++) outp[i] = 0;
        Buffer.BlockCopy(raw, start, outp, 32 - len, len);
        return true;
    }

    // ---- pubkey canonical encoding (Rule 4; on-curve is separate/injected) ----
    public static bool CanonicalPubkeyEncoding(byte[] pub)
    {
        if (pub.Length == 33 && (pub[0] == 0x02 || pub[0] == 0x03))
            return CompareBe(pub.AsSpan(1, 32), SECP_P) < 0;
        if (pub.Length == 65 && pub[0] == 0x04)
            return CompareBe(pub.AsSpan(1, 32), SECP_P) < 0 && CompareBe(pub.AsSpan(33, 32), SECP_P) < 0;
        return false; // hybrid 0x06/0x07, wrong length, bad prefix
    }

    // ---- P2SH multisig redeemScript template (Rule 2) ----
    private static bool ParseMultisigRedeem(byte[] redeem, out int m, out List<byte[]> keys)
    {
        m = 0; keys = new List<byte[]>();
        var ops = ParseScript(redeem);
        if (ops == null || ops.Count < 4) return false;
        // OP_m, n×key, OP_n, OP_CHECKMULTISIG
        if (!IsSmallNum(ops[0].op, out int mm)) return false;
        if (ops[^1].op != 0xAE) return false;                    // OP_CHECKMULTISIG
        if (!IsSmallNum(ops[^2].op, out int nn)) return false;   // OP_n
        int keyCount = ops.Count - 3;
        if (keyCount != nn) return false;
        if (!(mm >= 1 && mm <= nn && nn <= 15)) return false;
        for (int i = 1; i <= keyCount; i++)
        {
            var op = ops[i];
            if (op.op != 0x21 || op.dataLen != 33) return false; // exactly 0x21 push of 33 bytes
            byte[] key = Slice(redeem, op);
            if (key[0] != 0x02 && key[0] != 0x03) return false;  // compressed only
            keys.Add(key);
        }
        m = mm;
        return true;
    }

    private static bool IsSmallNum(int op, out int val)
    {
        if (op >= 0x51 && op <= 0x60) { val = op - 0x50; return true; } // OP_1..OP_16
        val = 0; return false;
    }

    // ---- script parsing with minimal-push enforcement ----
    private static bool IsPush(int op) => op <= 0x4E;

    /// <summary>Parse a script into ops; enforce minimal pushes; null on malformed/non-minimal.</summary>
    private static List<(int op, int dataOff, int dataLen)>? ParseScript(byte[] s)
    {
        var ops = new List<(int, int, int)>();
        int i = 0;
        while (i < s.Length)
        {
            int op = s[i];
            if (op < 0x4C) // direct push of `op` bytes
            {
                int len = op;
                if (i + 1 + len > s.Length) return null;
                ops.Add((op, i + 1, len));
                i += 1 + len;
            }
            else if (op == 0x4C) // PUSHDATA1
            {
                if (i + 2 > s.Length) return null;
                int len = s[i + 1];
                if (len < 76) return null;                  // non-minimal
                if (i + 2 + len > s.Length) return null;
                ops.Add((op, i + 2, len));
                i += 2 + len;
            }
            else if (op == 0x4D) // PUSHDATA2
            {
                if (i + 3 > s.Length) return null;
                int len = s[i + 1] | (s[i + 2] << 8);
                if (len < 256) return null;                 // non-minimal
                if (len > 520 || i + 3 + len > s.Length) return null;
                ops.Add((op, i + 3, len));
                i += 3 + len;
            }
            else if (op == 0x4E) // PUSHDATA4 (out of range for our templates)
            {
                return null;
            }
            else // non-push opcode (OP_0 handled as op=0x00 above is <0x4C; OP_1..16, OP_CHECKMULTISIG, etc.)
            {
                ops.Add((op, i + 1, 0));
                i += 1;
            }
        }
        return ops;
    }

    private static byte[] Slice(byte[] s, (int op, int dataOff, int dataLen) o)
    {
        byte[] r = new byte[o.dataLen];
        Buffer.BlockCopy(s, o.dataOff, r, 0, o.dataLen);
        return r;
    }

    // ---- scriptCode + legacy sighash incl. FindAndDelete ----
    public static byte[] P2pkhScriptCode(byte[] hash160)
    {
        // OP_DUP OP_HASH160 <0x14 hash> OP_EQUALVERIFY OP_CHECKSIG
        byte[] sc = new byte[25];
        sc[0] = 0x76; sc[1] = 0xA9; sc[2] = 0x14;
        Buffer.BlockCopy(hash160, 0, sc, 3, 20);
        sc[23] = 0x88; sc[24] = 0xAC;
        return sc;
    }

    public static byte[] LegacySighash(RawTx tx, int k, byte[] scriptCode, byte[][] checkedSigs)
    {
        // FindAndDelete each checked signature's push from scriptCode (host-consensus semantics).
        byte[] sc = scriptCode;
        foreach (var sig in checkedSigs)
            sc = FindAndDelete(sc, PushOf(sig));

        var b = new List<byte>();
        WriteI32LE(b, tx.Version);
        WriteVarInt(b, (ulong)tx.Inputs.Count);
        for (int i = 0; i < tx.Inputs.Count; i++)
        {
            var inp = tx.Inputs[i];
            b.AddRange(inp.PrevHash);
            WriteU32LE(b, inp.PrevN);
            byte[] script = (i == k) ? sc : Array.Empty<byte>();
            WriteVarInt(b, (ulong)script.Length);
            b.AddRange(script);
            WriteU32LE(b, inp.Sequence);
        }
        WriteVarInt(b, (ulong)tx.Outputs.Count);
        foreach (var o in tx.Outputs)
        {
            WriteI64LE(b, o.Value);
            WriteVarInt(b, (ulong)o.ScriptPubKey.Length);
            b.AddRange(o.ScriptPubKey);
        }
        WriteU32LE(b, tx.Locktime);
        WriteU32LE(b, 0x00000001); // hashtype as 4-byte LE int32 (NEVER 1 byte) — §4 step 4
        return Hashing.DoubleSha256(b.ToArray());
    }

    /// <summary>Bitcoin Core CScript::FindAndDelete semantics: boundary-aligned removal of `pattern`.</summary>
    public static byte[] FindAndDelete(byte[] script, byte[] pattern)
    {
        if (pattern.Length == 0) return script;
        var outp = new List<byte>();
        int pc = 0;
        while (pc < script.Length)
        {
            if (pc + pattern.Length <= script.Length && MatchAt(script, pc, pattern))
            {
                pc += pattern.Length; // delete
                continue;
            }
            int sz = OpSize(script, pc);
            if (sz <= 0) { for (int j = pc; j < script.Length; j++) outp.Add(script[j]); break; }
            for (int j = 0; j < sz && pc + j < script.Length; j++) outp.Add(script[pc + j]);
            pc += sz;
        }
        return outp.ToArray();
    }

    private static bool MatchAt(byte[] s, int off, byte[] p)
    {
        for (int i = 0; i < p.Length; i++) if (s[off + i] != p[i]) return false;
        return true;
    }

    private static int OpSize(byte[] s, int pc)
    {
        int op = s[pc];
        if (op < 0x4C) return 1 + op;
        if (op == 0x4C) return pc + 1 < s.Length ? 2 + s[pc + 1] : 1;
        if (op == 0x4D) return pc + 2 < s.Length ? 3 + (s[pc + 1] | (s[pc + 2] << 8)) : 1;
        if (op == 0x4E) return pc + 4 < s.Length ? 5 + (s[pc + 1] | (s[pc + 2] << 8) | (s[pc + 3] << 16) | (s[pc + 4] << 24)) : 1;
        return 1;
    }

    private static byte[] PushOf(byte[] data)
    {
        // minimal push encoding of `data` (sig pushes are 71-73 bytes → direct push)
        if (data.Length < 0x4C)
        {
            byte[] r = new byte[1 + data.Length];
            r[0] = (byte)data.Length;
            Buffer.BlockCopy(data, 0, r, 1, data.Length);
            return r;
        }
        byte[] r2 = new byte[2 + data.Length];
        r2[0] = 0x4C; r2[1] = (byte)data.Length;
        Buffer.BlockCopy(data, 0, r2, 2, data.Length);
        return r2;
    }

    // ---- big-endian helpers ----
    private static int CompareBe(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => ByteArrayComparer.CompareSpan(a, b);

    private static byte[] Hex(string s)
    {
        byte[] r = new byte[s.Length / 2];
        for (int i = 0; i < r.Length; i++) r[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
        return r;
    }

    private static void WriteI32LE(List<byte> b, int v) { for (int i = 0; i < 4; i++) b.Add((byte)(v >> (8 * i))); }
    private static void WriteU32LE(List<byte> b, uint v) { for (int i = 0; i < 4; i++) b.Add((byte)(v >> (8 * i))); }
    private static void WriteI64LE(List<byte> b, long v) { for (int i = 0; i < 8; i++) b.Add((byte)(v >> (8 * i))); }
    private static void WriteVarInt(List<byte> b, ulong v)
    {
        if (v < 0xFD) b.Add((byte)v);
        else if (v <= 0xFFFF) { b.Add(0xFD); b.Add((byte)v); b.Add((byte)(v >> 8)); }
        else if (v <= 0xFFFFFFFF) { b.Add(0xFE); for (int i = 0; i < 4; i++) b.Add((byte)(v >> (8 * i))); }
        else { b.Add(0xFF); for (int i = 0; i < 8; i++) b.Add((byte)(v >> (8 * i))); }
    }
}
