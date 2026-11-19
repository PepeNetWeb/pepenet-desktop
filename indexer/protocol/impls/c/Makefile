# protocol-sm — C reference implementation (zero external deps).
#
#   make         build ./sm
#   make test    build + run the self-test (PRNG/digest sanity + invariant battery)
#   make run     ./sm random 42 100000
#   make fuzz N=1000000 SEED=42
#   make clean
#
# Only a C11 compiler is required. __int128 is used for the 128-bit money / vote
# accumulator math (clang/gcc extension; pinned in SPEC-conformance.md).

CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wno-unused-parameter
SRC     := $(wildcard src/*.c)
HDR     := $(wildcard src/*.h)

N    ?= 1000000
SEED ?= 42

sm: $(SRC) $(HDR)
	$(CC) $(CFLAGS) -o $@ $(SRC)

test: sm
	./sm selftest

run: sm
	./sm random 42 100000

fuzz: sm
	./sm random $(SEED) $(N)

cover: sm
	./sm coverage 42 300000

# UndefinedBehaviorSanitizer over every mode — catches signed-overflow / OOB-index /
# bad-shift UB (the 128-bit money + vote math, the byte decoder) that the digest
# equality can't see. `-fno-sanitize-recover` makes any UB a hard, non-zero exit.
SANFLAGS := -fsanitize=undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g -O1
sanitize: $(SRC) $(HDR)
	$(CC) -std=c11 -Wall -Wextra -Wno-unused-parameter $(SANFLAGS) -o sm.san $(SRC)
	./sm.san selftest
	./sm.san random     42 80000  >/dev/null
	./sm.san fuzz       42 80000  >/dev/null
	./sm.san bfuzz      42 80000  >/dev/null
	./sm.san properties 42 80000  >/dev/null
	./sm.san reorg      42 6000   >/dev/null
	./sm.san reorgfuzz  42 6000   >/dev/null
	./sm.san meta       42 20000  >/dev/null
	./sm.san coverage   42 150000 >/dev/null
	./sm.san scenario             >/dev/null
	./sm.san attrib-selftest      >/dev/null
	./sm.san attrib     42 40000  >/dev/null
	./sm.san attrib-scenario      >/dev/null
	./sm.san attrib-curve         >/dev/null
	./sm.san ecmh                 >/dev/null
	@echo "sanitizer: clean (ubsan, all modes)"

# AddressSanitizer pass (memory bugs). NOTE: the ASan *runtime* hangs at startup on
# some macOS builds (Darwin 25) — even a trivial program — so this target may not run
# locally; it works in CI/Linux. Kept separate from `sanitize` for that reason.
asan: $(SRC) $(HDR)
	$(CC) -std=c11 -Wall -Wextra -Wno-unused-parameter -fsanitize=address -g -O1 -o sm.asan $(SRC)
	ASAN_OPTIONS=detect_leaks=1 ./sm.asan selftest && ./sm.asan reorgfuzz 42 4000 >/dev/null && ./sm.asan meta 42 12000 >/dev/null
	@echo "asan: clean"

clean:
	rm -f sm sm.san sm.asan

.PHONY: test run fuzz cover sanitize asan clean
