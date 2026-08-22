# pepenet-desktop test harness.
#
# The app itself is a GUI binary built by CMake; these tests deliberately do
# NOT go through it. Each test links only the pure modules it exercises
# (wallet math, bip39/hdwallet, fee, ops encoding, the PAC front door …), so a
# suite run needs no window server, no network, and no Metal — it is a plain
# `make check` that finishes in seconds and is safe in CI and over ssh.
#
# House style matches the sibling repos: one self-contained C file per area,
# a CHECK(cond,"name") line per assertion, "N ok, M failed" at the end,
# non-zero exit on any failure.
#
# Build fragments live in mk/*.mk — one per area, each owning its own targets.
# Add a new area by dropping in mk/<area>.mk and appending to TESTS there;
# nothing else needs editing.

ROOT    := $(CURDIR)/..
SRC     := $(ROOT)/src
IDX     := $(ROOT)/indexer/src
SM      := $(ROOT)/indexer/protocol/impls/c/src
SECPDIR := $(ROOT)/indexer/vendor/secp256k1
SECPLIB := $(ROOT)/indexer/build/secp/lib/libsecp256k1.a
SHIM    := $(ROOT)/indexer/protocol/shim/secp_shim.c
DNSSRC  := $(ROOT)/dns/src
MESHINC := $(ROOT)/mesh/include
TLSSRC  := $(ROOT)/tls/src

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
OPENSSL ?= /opt/homebrew/opt/openssl@3
OPENSSL_INC := -I$(OPENSSL)/include
else
OPENSSL_INC := $(shell pkg-config --cflags openssl)
endif

CC      ?= cc
# -Isrc first, then libsecp's include, then the protocol headers: the same
# include-order dance the app's CMakeLists documents (quoted "secp256k1.h"
# from indexer sources must find the VENDORED header, not the protocol's).
CFLAGS  ?= -std=c11 -O1 -g -Wall -Wextra -Wno-unused-parameter
INC     := -I$(SRC) -I$(IDX) -I$(SECPDIR)/include -I$(SM) -I$(DNSSRC) -I$(MESHINC)
LDLIBS  := $(SECPLIB) -lsqlite3

# Sanitizer build: `make SAN=1 check` rebuilds everything with ASan+UBSan.
ifdef SAN
CFLAGS  += -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined
LDFLAGS += -fsanitize=address,undefined
endif
# Thread-sanitizer build for the jitter suites: `make TSAN=1 check-jitter`.
ifdef TSAN
CFLAGS  += -fsanitize=thread -g
LDFLAGS += -fsanitize=thread
endif
# Coverage build: `make COV=1 check` then `make cover-report`.
ifdef COV
CFLAGS  += -fprofile-instr-generate -fcoverage-mapping
LDFLAGS += -fprofile-instr-generate
endif

TESTS   :=
JITTER  :=

include $(wildcard mk/*.mk)

all: $(TESTS) $(JITTER)

# The fast suite: deterministic, hermetic, no sockets beyond loopback.
check: $(TESTS)
	@fail=0; for t in $(TESTS); do \
	  echo "── $$t"; ./$$t || fail=1; echo; \
	done; \
	if [ $$fail -ne 0 ]; then echo "SUITE FAILED"; exit 1; fi; \
	echo "all desktop suites passed"

# The jitter/concurrency suites are separated: they are slower, they bind
# loopback ports, and they are the ones worth running under TSAN=1.
check-jitter: $(JITTER)
	@fail=0; for t in $(JITTER); do \
	  echo "── $$t"; ./$$t || fail=1; echo; \
	done; \
	if [ $$fail -ne 0 ]; then echo "JITTER SUITE FAILED"; exit 1; fi; \
	echo "all jitter suites passed"

$(SECPLIB):
	$(MAKE) -C $(ROOT)/indexer $(SECPLIB)

clean:
	rm -f $(TESTS) $(JITTER) *.o *.profraw *.profdata
	rm -rf *.dSYM

.PHONY: all check check-jitter clean
