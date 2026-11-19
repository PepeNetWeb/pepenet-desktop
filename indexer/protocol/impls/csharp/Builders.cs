using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace Pepenet;

/// <summary>Convenience builders for hand-authored vectors (selftest / scenario).</summary>
public static class B
{
    // generator identity convention (SPEC-conformance §5): h160 = byte(i) ‖ 18 zero ‖ byte(i)
    public static byte[] Id(int i) { var h = new byte[20]; h[0] = (byte)i; h[19] = (byte)i; return h; }
    public static byte IdType(int i) => (i % 4 == 3) ? K.TYPE_P2SH : K.TYPE_P2PKH;

    public static Input In(int id, bool sah = true) => new() { H160 = Id(id), Type = IdType(id), SighashAll = sah };
    public static Out Spend(int id, ulong val) => Out.Spend(Id(id), IdType(id), val);
    public static Out Spend(byte[] h160, byte type, ulong val) => Out.Spend(h160, type, val);

    public static byte[] Name(string s) => System.Text.Encoding.ASCII.GetBytes(s);

    public static byte[] Payload(byte op, byte[] body)
    {
        byte[] p = new byte[4 + body.Length];
        p[0] = K.PFX0; p[1] = K.PFX1; p[2] = K.PFX2; p[3] = op;
        Buffer.BlockCopy(body, 0, p, 4, body.Length);
        return p;
    }

    public static byte[] U32(uint v) { byte[] b = new byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(b, v); return b; }
    public static byte[] U64(ulong v) { byte[] b = new byte[8]; BinaryPrimitives.WriteUInt64LittleEndian(b, v); return b; }
    public static byte[] U40(long v) { byte[] b = new byte[5]; for (int i = 0; i < 5; i++) b[i] = (byte)(v >> (8 * i)); return b; }

    public static byte[] Concat(params byte[][] parts)
    {
        int n = 0; foreach (var p in parts) n += p.Length;
        byte[] r = new byte[n]; int o = 0;
        foreach (var p in parts) { Buffer.BlockCopy(p, 0, r, o, p.Length); o += p.Length; }
        return r;
    }

    public static byte[] Salt(byte b) { var s = new byte[32]; for (int i = 0; i < 32; i++) s[i] = b; return s; }

    public static byte[] Commitment(byte[] salt, byte[] name, byte[] author)
        => Hashing.Sha256(Concat(salt, name, author));

    // ---- payload builders ----
    public static byte[] Commit(byte[] commitment) => Payload(K.OP_COMMIT, commitment);
    public static byte[] Claim(byte[] salt, string name) => Payload(K.OP_CLAIM, Concat(salt, Name(name)));
    public static byte[] RenewAll() => Payload(K.OP_RENEW, Array.Empty<byte>());
    public static byte[] RenewAllSafe(long anchor) => Payload(K.OP_RENEW, U40(anchor));
    public static byte[] RenewSel(long anchor, byte[] flags) => Payload(K.OP_RENEW, Concat(U40(anchor), flags));
    public static byte[] TransferAll(byte[] target) => Payload(K.OP_TRANSFER, target);
    public static byte[] TransferSel(byte[] target, long anchor, byte[] flags) => Payload(K.OP_TRANSFER, Concat(target, U40(anchor), flags));
    public static byte[] Release(long anchor, byte[] flags) => Payload(K.OP_RELEASE, Concat(U40(anchor), flags));
    public static byte[] Sell(ulong price, uint window, string name) => Payload(K.OP_SELL, Concat(U64(price), U32(window), Name(name)));
    public static byte[] Reserve(string name) => Payload(K.OP_RESERVE, Name(name));
    public static byte[] Settle(string name) => Payload(K.OP_SETTLE, Name(name));
    public static byte[] SellTo(ulong price, byte[] buyer, string name) => Payload(K.OP_SELL_TO, Concat(U64(price), buyer, Name(name)));
    public static byte[] Pay(string name) => Payload(K.OP_PAY, Name(name));
    public static byte[] As(byte index) => Payload(K.OP_AS, new[] { index });
    public static byte[] Trade(byte idxA, byte idxB, string nameA, string nameB)
        => Payload(K.OP_TRADE, Concat(new[] { idxA, idxB }, Name(nameA), new byte[] { 0x2C }, Name(nameB)));
}
