package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
)

func main() {
	mode := "selftest"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "selftest":
		runSelftest()
	case "scenario":
		runScenario()
	case "forkvectors":
		runForkvectors()
	case "attrib-selftest":
		runAttribSelftest()
	case "attrib-curve":
		runAttribCurve()
	case "ecmh":
		runEcmh()
	case "properties":
		seed, count := modeArgs()
		runProperties(seed, count)
	case "meta":
		seed, count := modeArgs()
		runMeta(seed, count)
	case "reorg":
		seed, count := modeArgs()
		runReorg(seed, count)
	case "reorgfuzz":
		seed, count := modeArgs()
		runReorgfuzz(seed, count)
	case "fuzz":
		seed, count := modeArgs()
		runFuzz(seed, count)
	case "digest":
		// Dump a digest of a tiny demo state.
		s := newState()
		fmt.Printf("empty state_digest=%s\n", hex.EncodeToString(must32(s.stateDigest())))
	case "prng":
		p := newPRNG(0)
		fmt.Printf("first=%016X\n", p.next())
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q; modes: selftest scenario forkvectors attrib-selftest attrib-curve ecmh properties meta reorg reorgfuzz fuzz digest prng\n", mode)
		os.Exit(2)
	}
}

func must32(a [32]byte) []byte { return a[:] }

// modeArgs parses `<seed> <count>` for the generator-driven modes.
func modeArgs() (uint64, int) {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "usage: sm %s <seed> <count>\n", os.Args[1])
		os.Exit(2)
	}
	seed, err1 := strconv.ParseUint(os.Args[2], 10, 64)
	count, err2 := strconv.Atoi(os.Args[3])
	if err1 != nil || err2 != nil {
		fmt.Fprintf(os.Stderr, "bad seed/count\n")
		os.Exit(2)
	}
	return seed, count
}
