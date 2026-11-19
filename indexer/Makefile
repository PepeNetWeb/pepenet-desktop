# PepeNet headless indexer (C reference)
#
# Links the protocol reference fold (protocol/impls/c/src, a pinned submodule of
# namespace-protocol) as its consensus engine — compile-in-place, so the daemon
# folds byte-for-byte identically to the executable spec. The only new
# consensus-relevant code is this repo's adapter (real Dogecoin block/tx ->
# abstract SmTx) + §4 attribution.
#
#   make            build ./indexerd (builds vendored libsecp first)
#   make test       build + run the selftest
#   make check      the extra test suites (db, sync, codec, serve, accept, net_policy, snapshot)
#   make help       list targets, commands and docs
#   make clean
#
# First checkout: git submodule update --init --recursive
#
# EC crypto is the audited vendored libsecp256k1 (verify + ECMH only — indexerd
# ships NO secret-key curve math). The self-rolled secp256k1.c from the protocol
# repo is deliberately NOT compiled here; protocol/shim/secp_shim.c re-implements
# its header on libsecp.

CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wno-unused-parameter
# -std=c11 hides POSIX/GNU prototypes on glibc (gmtime_r, getaddrinfo, ...);
# appended even to a command-line CFLAGS so `make check` builds on Linux.
override CFLAGS += -D_GNU_SOURCE
SMDIR   := protocol/impls/c/src
SHIM    := protocol/shim/secp_shim.c
SECPDIR := vendor/secp256k1
SECPLIB := build/secp/lib/libsecp256k1.a

# Curve-free fold + canonical SHA-256 digest (the consensus core).
ENGINE_CORE := fold decode oracle digest state lease market claim trade bitmap \
               preblock sha256 ripemd160 gen harness
ENGINE_SRCS := $(addprefix $(SMDIR)/,$(addsuffix .c,$(ENGINE_CORE)))

# Curve-dependent engine bits (ECMH published digest). attrib.c/attrib_curve.c are
# NOT linked — the daemon has its own real-tx attribution (src/attrib.c).
ENGINE_CURVE := ecmh
ENGINE_CURVE_SRCS := $(addprefix $(SMDIR)/,$(addsuffix .c,$(ENGINE_CURVE)))

# Indexer sources.
IDX_SRCS := src/main.c src/attrib.c src/adapter.c src/oracle_feed.c \
            src/db.c src/chain.c src/base58.c src/sync.c src/pow.c src/serve_store.c \
            src/txcheck.c src/mempool.c src/net_policy.c src/snapshot.c src/dbcheck.c $(SHIM) src/test_chain.c

# sqlite. Default: the system library via pkg-config (unchanged).
# Pinned build: SQLITE_AMALGAMATION=<dir with sqlite3.c + sqlite3.h> compiles that
# amalgamation in statically. SQLITE_PIN_VERSION (if set) must equal the header's
# SQLITE_VERSION and SQLITE_PIN_SHA256 (if set) the sha256 of sqlite3.c, or the
# build stops. Nothing is downloaded; see docs/SQLITE-PIN.md for the recommended
# release and hashes.
.DEFAULT_GOAL := all
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
SQLITE_CFLAGS := $(shell pkg-config --cflags sqlite3 2>/dev/null)
SQLITE_LIBS   := $(shell pkg-config --libs sqlite3 2>/dev/null || echo -lsqlite3)
SQLITE_OBJ    :=
else
SQLITE_OBJ    := build/sqlite/sqlite3.o
SQLITE_CFLAGS := -I$(SQLITE_AMALGAMATION)
SQLITE_LIBS   := $(SQLITE_OBJ) -lm $(SQLITE_DL)
SQLITE_DEFS   := -DSQLITE_THREADSAFE=1 -DSQLITE_DEFAULT_PAGE_SIZE=4096 -DSQLITE_OMIT_LOAD_EXTENSION \
                 -DSQLITE_DQS=0 -DSQLITE_DEFAULT_MEMSTATUS=0
$(SQLITE_OBJ): $(SQLITE_AMALGAMATION)/sqlite3.c $(SQLITE_AMALGAMATION)/sqlite3.h
	@v=$$(sed -n 's/^#define SQLITE_VERSION  *"\(.*\)"/\1/p' $(SQLITE_AMALGAMATION)/sqlite3.h); \
	 if [ -n "$(SQLITE_PIN_VERSION)" ] && [ "$$v" != "$(SQLITE_PIN_VERSION)" ]; then \
	   echo "sqlite pin: amalgamation is $$v, expected $(SQLITE_PIN_VERSION)" >&2; exit 1; fi; \
	 if [ -n "$(SQLITE_PIN_SHA256)" ]; then \
	   if command -v sha256sum >/dev/null 2>&1; then h=$$(sha256sum $(SQLITE_AMALGAMATION)/sqlite3.c | cut -d' ' -f1); \
	   elif command -v shasum >/dev/null 2>&1; then h=$$(shasum -a 256 $(SQLITE_AMALGAMATION)/sqlite3.c | cut -d' ' -f1); \
	   else echo "sqlite pin: need sha256sum or shasum to check SQLITE_PIN_SHA256" >&2; exit 1; fi; \
	   if [ "$$h" != "$(SQLITE_PIN_SHA256)" ]; then echo "sqlite pin: sqlite3.c sha256 $$h, expected $(SQLITE_PIN_SHA256)" >&2; exit 1; fi; fi; \
	 echo "sqlite: vendored amalgamation $$v"
	@mkdir -p build/sqlite
	$(CC) -O2 -w $(SQLITE_DEFS) -c -o $@ $(SQLITE_AMALGAMATION)/sqlite3.c
endif

# Order matters: both the protocol repo and libsecp ship a header literally named
# "secp256k1.h". Engine files include theirs *quoted* (own-dir-first, = SMDIR), so
# putting the libsecp include dir ahead only affects ANGLE includes — secp_shim.c's
# `#include <secp256k1.h>` then unambiguously gets the vendored library.
INCLUDES := -Isrc -I$(SECPDIR)/include -I$(SMDIR)
# idx-11: link hooks. Static or cross builds add to these; don't override LIBS
# on the command line (`make LIBS+=...` there REPLACES LIBS and drops
# libsecp256k1, sqlite and -lpthread):
#   make EXTRA_LDFLAGS=-static EXTRA_LIBS='-lm'
# EXTRA_LDFLAGS (and any LDFLAGS) go before the objects; EXTRA_LIBS last.
EXTRA_LDFLAGS ?=
EXTRA_LIBS    ?=
LINK_FLAGS  = $(LDFLAGS) $(EXTRA_LDFLAGS)
LIBS     := $(SECPLIB) $(SQLITE_LIBS) -lpthread $(EXTRA_LIBS)

ALL_SRCS := $(ENGINE_SRCS) $(ENGINE_CURVE_SRCS) $(IDX_SRCS)

all: indexerd

# Vendored libsecp256k1, built once via its own CMake (static, minimal modules).
$(SECPLIB): $(SECPDIR)/CMakeLists.txt
	cmake -S $(SECPDIR) -B build/secp -DCMAKE_BUILD_TYPE=Release \
	      -DBUILD_SHARED_LIBS=OFF -DSECP256K1_BUILD_BENCHMARK=OFF \
	      -DSECP256K1_BUILD_TESTS=OFF -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF \
	      -DSECP256K1_BUILD_CTIME_TESTS=OFF -DSECP256K1_BUILD_EXAMPLES=OFF \
	      -DSECP256K1_INSTALL=OFF -DSECP256K1_ENABLE_MODULE_ECDH=ON \
	      -DSECP256K1_ENABLE_MODULE_RECOVERY=OFF -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=OFF \
	      -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=OFF -DSECP256K1_ENABLE_MODULE_MUSIG=OFF \
	      -DSECP256K1_ENABLE_MODULE_ELLSWIFT=OFF >/dev/null
	cmake --build build/secp -j >/dev/null

indexerd: $(ALL_SRCS) $(wildcard src/*.h) $(wildcard $(SMDIR)/*.h) $(SECPLIB) $(SQLITE_OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) $(SQLITE_CFLAGS) $(LINK_FLAGS) -o $@ $(ALL_SRCS) $(LIBS)

test: indexerd
	./indexerd selftest

clean:
	rm -rf indexerd indexerd.san indexerd-stalltest build

.PHONY: all test clean

# ── extra test suites (storage / sync / codec) ────────────────────────────────
# Appended targets; `test` above is untouched and still runs ./indexerd selftest.
# Each suite links the same objects as indexerd with src/main.c swapped out for
# the suite's own main (test_chain.c stays in — sync.c's selftest path needs it).
TEST_SRCS := $(filter-out src/main.c,$(ALL_SRCS))

test_db: $(TEST_SRCS) src/test_db.c $(SECPLIB) $(SQLITE_OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) $(SQLITE_CFLAGS) $(LINK_FLAGS) -o $@ $(TEST_SRCS) src/test_db.c $(LIBS)

test_sync: $(TEST_SRCS) src/test_sync.c $(SECPLIB) $(SQLITE_OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) $(SQLITE_CFLAGS) $(LINK_FLAGS) -o $@ $(TEST_SRCS) src/test_sync.c $(LIBS)

# test_serve_accept: production idx_serve accept/dial loop (slow outbound must
# not starve inbound handshake, burst accept, EOF frees cap seats).
test_serve_accept: $(TEST_SRCS) src/test_serve_accept.c $(SECPLIB) $(SQLITE_OBJ)
	$(CC) $(CFLAGS) -DIDX_SERVE_TEST $(INCLUDES) $(SQLITE_CFLAGS) $(LINK_FLAGS) -o $@ $(TEST_SRCS) src/test_serve_accept.c $(LIBS)

# Same-IP gossip seating: production idx_serve + real dns_net + real sp_state.
# Mesh/DNS objects use INC without vendored libsecp so quoted "secp256k1.h"
# resolves to the protocol-sm shim (same dance as dns/Makefile INC_MESH/INC_DNS).
GOSSIP_MESH_SRCS := ../mesh/src/crypto.c ../mesh/src/view.c ../mesh/src/wire.c ../mesh/src/state.c
GOSSIP_DNS_SRCS  := ../dns/src/dns_net.c ../dns/src/dns_state.c ../dns/src/zone.c ../dns/src/dns_wire.c
GOSSIP_MESH_INC  := -I../mesh/include -I$(SMDIR)
GOSSIP_DNS_INC   := -I../dns/src -I../mesh/include -I$(SMDIR) -Isrc
GOSSIP_MESH_OBJS := $(patsubst ../mesh/src/%.c,build/gossip-mesh/%.o,$(GOSSIP_MESH_SRCS))
GOSSIP_DNS_OBJS  := $(patsubst ../dns/src/%.c,build/gossip-dns/%.o,$(GOSSIP_DNS_SRCS))
build/gossip-mesh/%.o: ../mesh/src/%.c
	@mkdir -p build/gossip-mesh
	$(CC) $(CFLAGS) $(GOSSIP_MESH_INC) -c $< -o $@
build/gossip-dns/%.o: ../dns/src/%.c
	@mkdir -p build/gossip-dns
	$(CC) $(CFLAGS) $(GOSSIP_DNS_INC) $(SQLITE_CFLAGS) -c $< -o $@
test_serve_gossip: $(TEST_SRCS) src/test_serve_gossip.c $(GOSSIP_MESH_OBJS) $(GOSSIP_DNS_OBJS) $(SECPLIB) $(SQLITE_OBJ)
	$(CC) $(CFLAGS) -DIDX_SERVE_TEST $(INCLUDES) -I../dns/src -I../mesh/include $(SQLITE_CFLAGS) $(LINK_FLAGS) -o $@ \
	  $(TEST_SRCS) src/test_serve_gossip.c $(GOSSIP_MESH_OBJS) $(GOSSIP_DNS_OBJS) $(LIBS)

test_rollback: $(TEST_SRCS) src/test_rollback.c $(SECPLIB) $(SQLITE_OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) $(SQLITE_CFLAGS) $(LINK_FLAGS) -o $@ $(TEST_SRCS) src/test_rollback.c $(LIBS)

test_codec: $(TEST_SRCS) src/test_codec.c $(SECPLIB) $(SQLITE_OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) $(SQLITE_CFLAGS) $(LINK_FLAGS) -o $@ $(TEST_SRCS) src/test_codec.c $(LIBS)

# test_serve covers src/serve_store.c — the peer-facing getheaders/getblocks/
# getdata cache + the blockstage mailbox — which no other suite touches. It
# needs only serve_store.c and sqlite, so it links its own tiny composition
# rather than the full indexer object set.
test_serve: src/test_serve.c src/serve_store.c src/serve_store.h $(SQLITE_OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) $(SQLITE_CFLAGS) $(LINK_FLAGS) -o $@ src/test_serve.c src/serve_store.c $(SQLITE_LIBS) $(EXTRA_LIBS)

test_snapshot: $(TEST_SRCS) src/test_snapshot.c $(SECPLIB) $(SQLITE_OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) $(SQLITE_CFLAGS) $(LINK_FLAGS) -o $@ $(TEST_SRCS) src/test_snapshot.c $(LIBS)

test_net_policy: src/test_net_policy.c src/net_policy.c src/net_policy.h $(SQLITE_OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) $(LINK_FLAGS) -o $@ src/test_net_policy.c src/net_policy.c $(EXTRA_LIBS)

# `make check` = the suites + test_peer_height.py. Run `make test` for the shipped selftest.
# Every suite runs even if an earlier one fails; the target fails if any did.
# indexerd-stalltest: indexerd with SHORT receive deadlines (batch 6 s, weigh
# 4 s, getblocks round 2 s, handshake 3 s) for scripts/test_sync_stall.py — the
# sync slow-loris regression. Same sources; only the four #ifndef deadlines differ.
STALL_DEFS := -DIDX_SYNC_BATCH_DEADLINE_S=6 -DIDX_SYNC_WEIGH_DEADLINE_S=4 \
              -DIDX_SYNC_ROUND_MS=2000 -DIDX_NET_SHAKE_DEADLINE_MS=3000
indexerd-stalltest: $(ALL_SRCS) $(wildcard src/*.h) $(wildcard $(SMDIR)/*.h) $(SECPLIB) $(SQLITE_OBJ)
	$(CC) $(CFLAGS) $(STALL_DEFS) $(INCLUDES) $(SQLITE_CFLAGS) $(LINK_FLAGS) -o $@ $(ALL_SRCS) $(LIBS)

check: test_db test_sync test_codec test_serve test_net_policy test_snapshot test_rollback test_serve_accept test_serve_gossip indexerd indexerd-stalltest
	@rc=0; for t in ./test_db ./test_sync ./test_codec ./test_serve ./test_net_policy ./test_snapshot ./test_rollback ./test_serve_accept ./test_serve_gossip; do \
	  echo "=== $$t ==="; $$t || rc=1; done; \
	echo "=== scripts/test_peer_height.py ==="; python3 scripts/test_peer_height.py ./indexerd || rc=1; \
	echo "=== scripts/test_sync_stall.py ==="; python3 scripts/test_sync_stall.py ./indexerd-stalltest || rc=1; \
	if [ $$rc -eq 0 ]; then echo "check: ALL PASSED"; else echo "check: FAILED"; fi; exit $$rc

check-clean:
	rm -f test_db test_sync test_codec test_serve test_net_policy test_snapshot test_rollback test_serve_accept test_serve_gossip indexerd-stalltest

.PHONY: check check-clean

# ── help ──────────────────────────────────────────────────────────────────────
help:
	@echo "targets:"
	@echo "  make              build ./indexerd (vendored libsecp first)"
	@echo "  make test         ./indexerd selftest (engine-link + shim goldens)"
	@echo "  make check        test_db test_sync test_codec test_serve test_net_policy test_snapshot test_rollback + test_peer_height.py"
	@echo "  make check-clean  remove the suite binaries"
	@echo "  make clean        remove indexerd and build/"
	@echo "commands: ./indexerd (no args) prints them; see docs/API.md"
	@echo "docs:     docs/QUICKSTART.md  docs/API.md  docs/SNAPSHOT.md  examples/"

.PHONY: help
