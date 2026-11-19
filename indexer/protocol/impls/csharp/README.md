# PepeNet namespace — C# reference implementation (Tier 2)

An independent C# implementation of the PepeNet namespace state machine, built from the
specification (`docs/protocol-spec.md` + `protocol-sm/SPEC-conformance.md`). It is part of the
cross-language conformance suite: each implementation is written independently and they
cross-validate the spec's consensus-critical outcomes. `impls/c` is the normative reference; the
consolidated rationale for the consensus-critical decisions lives in
[`SPEC-RATIONALE.md`](../../SPEC-RATIONALE.md).

BCL only — no NuGet, no external crypto. RIPEMD-160 and SplitMix64 are self-rolled; the secp256k1
`on_curve`/`verify` operations are the spec's **injected** byte-pseudo-functions, exactly as the
conformance doc prescribes.

## Build & run

Requires a current .NET SDK (built/tested on .NET 9; `Int128`/`UInt128` carry the ≥128-bit
computations). From this directory:

```
dotnet build -c Release
dotnet bin/Release/*/sm.dll selftest      # hand-authored vector battery + off-curve-P2PKH regression (69 checks)
dotnet bin/Release/*/sm.dll forkvectors   # the prose-pinned Tier-2 consensus-fork vectors (16/0)
dotnet bin/Release/*/sm.dll scenario      # named adversarial scenarios → per-scenario + combined digest
dotnet bin/Release/*/sm.dll digest 1 200  # this impl's OWN generator → state_digest (seed, count)
```

`run-conformance.sh` builds `sm.csproj` and runs `forkvectors` as part of the reference tier.

## Tier-2 role

This impl uses its **own** generator, so it does **not** reproduce the gen.c-pinned seed soak (Tier 1,
C-only) — that is by design, not a failure. Instead it cross-validates exactly what the **prose**
pins: `forkvectors` independently reproduces the spec-mandated outcome for the consensus-fork
differential vectors **TV-1, TV-5b, TV-6, TV-7, TV-8, M9, H8, H3** (16 asserts, 0 diverge). The
`selftest` includes the **off-curve-P2PKH** regression (a canonically-encoded but off-curve P2PKH
pubkey → §13 status 1 / on-curve-drop, carrying real identity + sighash). See SPEC-conformance.md
§"Two conformance tiers".

## C#-specific consensus-fork hazards avoided

`Int128`/`UInt128` carry the ≥128-bit computations (a silent `ulong`/`long` wrap would be a consensus
fork); the .NET replacing-UTF-8 decoder is replaced by a hand-rolled RFC-3629 validator; the unstable
`List.Sort` is replaced by an explicit insertion-index tiebreak; culture-sensitive comparison is
replaced by an explicit unsigned-bytewise comparer.

## Layout

`Constants.cs` `Prng.cs` `Ripemd160.cs` `Hashing.cs` (+ `ByteArrayComparer`) `Decoder.cs` `Model.cs`
`Lease.cs` `Oracle.cs` `Fold.cs` `Digest.cs` `Attribution.cs` `OwnGenerator.cs` `Scenarios.cs`
`SelfTest.cs` `Forkvectors.cs` `Program.cs`.
