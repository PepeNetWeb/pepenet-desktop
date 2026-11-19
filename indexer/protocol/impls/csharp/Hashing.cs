using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Pepenet;

public static class Hashing
{
    public static byte[] Sha256(ReadOnlySpan<byte> data)
    {
        Span<byte> outp = stackalloc byte[32];
        SHA256.HashData(data, outp);
        return outp.ToArray();
    }

    public static byte[] DoubleSha256(ReadOnlySpan<byte> data)
    {
        Span<byte> a = stackalloc byte[32];
        SHA256.HashData(data, a);
        Span<byte> b = stackalloc byte[32];
        SHA256.HashData(a, b);
        return b.ToArray();
    }

    /// <summary>hash160 = RIPEMD160(SHA256(x)) — the legacy identity (§4 / §0).</summary>
    public static byte[] Hash160(ReadOnlySpan<byte> data) => Ripemd160.Hash(Sha256(data));

    public static string Hex(ReadOnlySpan<byte> data)
    {
        var sb = new System.Text.StringBuilder(data.Length * 2);
        foreach (var b in data) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }
}

/// <summary>
/// Explicit UNSIGNED bytewise lexicographic comparer (brief: never rely on
/// default string/array ordering or culture-sensitive comparison). Used for
/// every byte[] digest sort key (names, owners, commitments, targets, txids).
/// </summary>
public sealed class ByteArrayComparer : IComparer<byte[]>
{
    public static readonly ByteArrayComparer Instance = new();

    public int Compare(byte[]? x, byte[]? y)
    {
        if (ReferenceEquals(x, y)) return 0;
        if (x is null) return -1;
        if (y is null) return 1;
        int n = Math.Min(x.Length, y.Length);
        for (int i = 0; i < n; i++)
        {
            int c = x[i].CompareTo(y[i]); // byte is unsigned 0..255 in C#
            if (c != 0) return c;
        }
        return x.Length.CompareTo(y.Length);
    }

    public static int CompareSpan(ReadOnlySpan<byte> x, ReadOnlySpan<byte> y)
    {
        int n = Math.Min(x.Length, y.Length);
        for (int i = 0; i < n; i++)
        {
            int c = x[i].CompareTo(y[i]);
            if (c != 0) return c;
        }
        return x.Length.CompareTo(y.Length);
    }
}
