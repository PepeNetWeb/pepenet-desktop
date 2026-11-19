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
# -D_DEFAULT_SOURCE: glibc + -std=c11 hides mkdtemp (t_dirscan). Harmless on Darwin.
CFLAGS  ?= -std=c11 -D_DEFAULT_SOURCE -O1 -g -Wall -Wextra -Wno-unused-parameter
INC     := -I$(SRC) -I$(IDX) -I$(SECPDIR)/include -I$(SM) -I$(DNSSRC) -I$(MESHINC)
# idx-08/09: SQLITE_AMALGAMATION=<dir> (+ SQLITE_PIN_VERSION/SQLITE_PIN_SHA256)
# links the indexer's pinned build/sqlite/sqlite3.o (built and checked by the
# indexer Makefile) instead of the platform -lsqlite3. Unset = unchanged.
# idx-10: MinGW/MSYS has no libdl (and OMIT_LOAD_EXTENSION means sqlite needs none)
ifeq ($(OS),Windows_NT)
SQLITE_DL :=
else ifneq ($(filter MINGW% MSYS% CYGWIN%,$(shell uname -s 2>/dev/null)),)
SQLITE_DL :=
else
SQLITE_DL := -ldl
endif
SQLITE_AMALGAMATION ?=
SQLITE_PIN_VERSION  ?=
SQLITE_PIN_SHA256   ?=
ifeq ($(strip $(SQLITE_AMALGAMATION)),)
SQLITE_OBJ  :=
SQLITE_LIBS := -lsqlite3
else
SQLITE_OBJ  := $(ROOT)/indexer/build/sqlite/sqlite3.o
SQLITE_LIBS := $(SQLITE_OBJ) -lm $(SQLITE_DL) -lpthread
INC         := -I$(SQLITE_AMALGAMATION) $(INC)
endif
LDLIBS  := $(SECPLIB) $(SQLITE_LIBS)
# idx-11: link hooks. Add flags/libraries here instead of overriding LIBS/LDLIBS
# on the command line (that replaces the list and drops libsecp256k1/sqlite):
#   make EXTRA_LDFLAGS=-static EXTRA_LIBS='-lpthread -lm'
# EXTRA_LDFLAGS joins LDFLAGS; EXTRA_LIBS goes last on every link line.
EXTRA_LDFLAGS ?=
EXTRA_LIBS    ?=
LDFLAGS += $(EXTRA_LDFLAGS)

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

ifneq ($(SQLITE_OBJ),)
$(SQLITE_OBJ):
	$(MAKE) -C $(ROOT)/indexer build/sqlite/sqlite3.o SQLITE_AMALGAMATION=$(SQLITE_AMALGAMATION) \
	  SQLITE_PIN_VERSION=$(SQLITE_PIN_VERSION) SQLITE_PIN_SHA256=$(SQLITE_PIN_SHA256)
$(TESTS) $(JITTER): | $(SQLITE_OBJ)
endif

$(SECPLIB):
	$(MAKE) -C $(ROOT)/indexer $(SECPLIB)

clean:
	rm -f $(TESTS) $(JITTER) *.o *.profraw *.profdata
	rm -rf *.dSYM

.PHONY: all check check-jitter clean

# Black-box greatdane-node checks (dane-01..03). Needs the cmake binary and a
# private netns:  unshare -rn sh -c 'ip link set lo up && make check-node'
check-node:
	./gd_node_test.sh ../build/greatdane-node
