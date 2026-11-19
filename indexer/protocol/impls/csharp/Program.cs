using System;
using System.Collections.Generic;

namespace Pepenet;

public static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length == 0) { Help(); return 0; }
        string mode = args[0];
        switch (mode)
        {
            case "selftest":
                return SelfTest.Run();
            case "forkvectors":
                return Forkvectors.Run();
            case "scenario":
                return Scenarios.Run();
            case "attrib-curve":
                return AttribCurve.Run();
            case "ecmh":
                return Ecmh.Run();
            case "properties":
            case "meta":
            case "reorg":
            case "reorgfuzz":
            case "fuzz":
            {
                ulong seed = args.Length > 1 ? ParseU64(args[1]) : 1;
                int count = args.Length > 2 ? int.Parse(args[2]) : 1000;
                return mode switch
                {
                    "properties" => Modes.Properties(seed, count),
                    "meta"       => Modes.Meta(seed, count),
                    "reorg"      => Modes.Reorg(seed, count),
                    "reorgfuzz"  => Modes.Reorgfuzz(seed, count),
                    "fuzz"       => Modes.Fuzz(seed, count),
                    _            => 0,
                };
            }
            case "digest":
            case "random":
            {
                ulong seed = args.Length > 1 ? ParseU64(args[1]) : 1;
                int count = args.Length > 2 ? int.Parse(args[2]) : 64;
                var f = OwnGenerator.Run(seed, count);
                Console.WriteLine($"state_digest={Digest.ComputeHex(f)}   (seed={seed} count={count})");
                Console.WriteLine("NOTE: this is THIS implementation's OWN generator. It is internally");
                Console.WriteLine("consistent but will NOT reproduce the reference's frozen seed-goldens,");
                Console.WriteLine("which depend on the forbidden reference generator/draw-order (SPEC §5/§6).");
                return 0;
            }
            case "help":
            default:
                Help();
                return 0;
        }
    }

    private static ulong ParseU64(string s) =>
        s.StartsWith("0x") ? Convert.ToUInt64(s.Substring(2), 16) : ulong.Parse(s);

    private static void Help()
    {
        Console.WriteLine("PepeNet clean-room reference (C#) — BCL only");
        Console.WriteLine("Usage:  dotnet run --project impl -- <mode>");
        Console.WriteLine("        (or from impl/:  dotnet run -- <mode>)");
        Console.WriteLine();
        Console.WriteLine("modes:");
        Console.WriteLine("  selftest            run the hand-authored vector battery (asserts outcomes)");
        Console.WriteLine("  forkvectors         run the prose-pinned Tier-2 consensus-fork vectors");
        Console.WriteLine("  scenario            print named scenario digests + combined");
        Console.WriteLine("  attrib-curve        §4 Strategy-B real secp256k1 curve-vector set");
        Console.WriteLine("  ecmh                §13.2 ECMH primitive vector set");
        Console.WriteLine("  digest <seed> <n>   run THIS impl's own generator and print state_digest");
        Console.WriteLine("  properties <s> <n>  §8 invariant battery (violations=0)");
        Console.WriteLine("  meta <s> <n>        §11 inert-tx no-op battery (failures=0)");
        Console.WriteLine("  reorg <s> <n>       §10 reorg confluence (failures=0)");
        Console.WriteLine("  reorgfuzz <s> <n>   §11 fork/divergence trials (failures=0)");
        Console.WriteLine("  fuzz <s> <n>        §9 decode/fold crash-safety (parser_crashes=0)");
        Console.WriteLine("  help                this message");
    }
}
