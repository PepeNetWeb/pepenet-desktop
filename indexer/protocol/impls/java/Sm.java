// PepeNet reference state-machine — INDEPENDENT Java implementation.
//
// Derived purely from docs/protocol-spec.md + protocol-sm/SPEC-conformance.md.
// NOT a port of any impls/* implementation (the point is fresh eyes for
// consensus bugs). Where prose is ambiguous, this impl follows the most
// natural reading and a divergence from a frozen golden is recorded as a
// finding rather than silently "fixed" to match.
//
// Run (no build step; Java 22+ multi-file source launch):
//   java impls/java/Sm.java selftest
//   java impls/java/Sm.java random <seed> <count>
//   ... (modes added incrementally)

import java.nio.charset.StandardCharsets;

public class Sm {
    public static void main(String[] args) {
        if (args.length == 0) { System.err.println("usage: sm <mode> [args]"); System.exit(2); }
        String mode = args[0];
        switch (mode) {
            case "selftest" -> Selftest.run();
            case "behav" -> Behav.run();
            case "attrib-scenario" -> AttribScenario.run();
            case "attrib-curve" -> AttribCurve.run();
            case "ecmh" -> Ecmh.run();
            case "random" -> Modes.random(Long.parseLong(args[1]), Integer.parseInt(args[2]));
            case "properties" -> Modes.properties(Long.parseLong(args[1]), Integer.parseInt(args[2]));
            case "meta" -> Modes.meta(Long.parseLong(args[1]), Integer.parseInt(args[2]));
            case "reorg" -> Modes.reorg(Long.parseLong(args[1]), Integer.parseInt(args[2]));
            case "fuzz" -> Modes.fuzz(Long.parseLong(args[1]), Integer.parseInt(args[2]));
            case "reorgfuzz" -> Modes.reorgfuzz(Long.parseLong(args[1]), Integer.parseInt(args[2]));
            case "scenario" -> Scenario.run();   // directed adversarial conformance vectors + rolling `combined` (mirrors impls/c)
            default -> { System.err.println("unknown mode: " + mode); System.exit(2); }
        }
    }

    static byte[] utf8(String s) { return s.getBytes(StandardCharsets.US_ASCII); }
}
