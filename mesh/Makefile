# pepenet-mesh — the shared substrate every pepenet overlay links.
#
# Produces a static lib (libpepenetnet.a) + headers under include/pepenet/.
# Hashes and the secp_* shim come from the live namespace-protocol tree (names-
# only SM); curve math is the vendored constant-time libsecp256k1 (built once
# under pepenet-social, same pin the carrier uses).
#
#   make            build lib + ./net_test
#   make check      build and run the self-test battery
#   make clean
#
# Header-collision note: the protocol repo and libsecp both ship "secp256k1.h".
# secp_shim.c includes the VENDOR one (angle); crypto.c needs protocol-sm's
# secp_* declarations (quoted) — resolved by compiling the two with different -I
# orders, then linking (same dance as namespace-indexer / carrier).

CC      ?= cc
# -std=c11 hides fdopen/mkdtemp on glibc (Ubuntu 24.04). _DEFAULT_SOURCE
# restores POSIX without switching the dialect to gnu11. Harmless on Darwin.
CFLAGS  ?= -std=c11 -D_DEFAULT_SOURCE -O2 -Wall -Wextra -Wshadow
AR      ?= ar

# Protocol-sm primitives (SHA-256 / RIPEMD-160 / secp_* interface + shim).
# Live namespace-protocol — not social's (often lagging) submodule pin.
PROTO   := ../namespace-protocol
SMDIR   := $(PROTO)/impls/c/src
SHIMSRC := $(PROTO)/shim/secp_shim.c

# Vendored libsecp256k1 — the indexer owns the build tree the family uses
# (pepenet-social, its previous home, is retired).
IDX     := ../namespace-indexer
SECPDIR := $(IDX)/vendor/secp256k1
SECPLIB := $(IDX)/build/secp/lib/libsecp256k1.a

SQLITE_CFLAGS := $(shell pkg-config --cflags sqlite3 2>/dev/null)
SQLITE_LIBS   := $(shell pkg-config --libs sqlite3 2>/dev/null || echo -lsqlite3)

B       := build
INC     := -Iinclude
INC_SM  := -I$(SMDIR)                            # protocol-sm's secp256k1.h (quoted)
INC_SHIM:= -I$(SECPDIR)/include -I$(SMDIR)       # vendored secp256k1.h (angle)

LIB     := libpepenetnet.a
# our own modules
OBJ     := $(B)/wire.o $(B)/view.o $(B)/crypto.o $(B)/state.o
# borrowed primitives, compiled into the same archive so consumers link one .a
PRIM    := $(B)/sha256.o $(B)/ripemd160.o $(B)/secp_shim.o

all: $(LIB) net_test state_test

$(LIB): $(OBJ) $(PRIM)
	$(AR) rcs $@ $^

net_test: $(B)/net_test.o $(LIB) $(SECPLIB)
	$(CC) $(CFLAGS) -o $@ $< $(LIB) $(SECPLIB) $(SQLITE_LIBS)

state_test: $(B)/state_test.o $(LIB) $(SECPLIB)
	$(CC) $(CFLAGS) -o $@ $< $(LIB) $(SECPLIB) $(SQLITE_LIBS)

$(B):
	mkdir -p $(B)

# our modules
$(B)/wire.o:   src/wire.c   | $(B); $(CC) $(CFLAGS) $(INC) -c -o $@ $<
$(B)/view.o:   src/view.c   | $(B); $(CC) $(CFLAGS) $(INC) $(SQLITE_CFLAGS) -c -o $@ $<
$(B)/crypto.o: src/crypto.c | $(B); $(CC) $(CFLAGS) $(INC) $(INC_SM) -c -o $@ $<
$(B)/state.o:  src/state.c  | $(B); $(CC) $(CFLAGS) $(INC) $(SQLITE_CFLAGS) -c -o $@ $<
$(B)/net_test.o: test/net_test.c | $(B); $(CC) $(CFLAGS) $(INC) $(SQLITE_CFLAGS) -c -o $@ $<
$(B)/state_test.o: test/state_test.c | $(B); $(CC) $(CFLAGS) $(INC) $(SQLITE_CFLAGS) -c -o $@ $<

# borrowed primitives
$(B)/sha256.o:    $(SMDIR)/sha256.c    | $(B); $(CC) $(CFLAGS) $(INC_SM) -c -o $@ $<
$(B)/ripemd160.o: $(SMDIR)/ripemd160.c | $(B); $(CC) $(CFLAGS) $(INC_SM) -c -o $@ $<
$(B)/secp_shim.o: $(SHIMSRC)           | $(B); $(CC) $(CFLAGS) $(INC_SHIM) -c -o $@ $<

# Vendored libsecp256k1 (the indexer's build tree; build it here if absent).
$(SECPLIB):
	cmake -S $(SECPDIR) -B $(IDX)/build/secp -DCMAKE_BUILD_TYPE=Release \
	      -DBUILD_SHARED_LIBS=OFF -DSECP256K1_BUILD_BENCHMARK=OFF -DSECP256K1_BUILD_TESTS=OFF \
	      -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF -DSECP256K1_BUILD_CTIME_TESTS=OFF \
	      -DSECP256K1_BUILD_EXAMPLES=OFF -DSECP256K1_INSTALL=OFF -DSECP256K1_ENABLE_MODULE_ECDH=ON \
	      -DSECP256K1_ENABLE_MODULE_RECOVERY=OFF -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=OFF \
	      -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=OFF -DSECP256K1_ENABLE_MODULE_MUSIG=OFF \
	      -DSECP256K1_ENABLE_MODULE_ELLSWIFT=OFF >/dev/null && cmake --build $(IDX)/build/secp -j >/dev/null

check: net_test state_test crypto_test wire_test view_test
	./net_test
	./state_test
	@rc=0; for t in crypto_test wire_test view_test; do \
	   echo "== ./$$t =="; ./$$t || rc=1; done; \
	 if [ $$rc -ne 0 ]; then \
	   echo "make check: a suite FAILED — see the FINDING banners above"; exit 1; \
	 fi; echo "make check: every suite passed"

clean:
	rm -rf $(B) $(LIB) net_test state_test
	rm -f crypto_test wire_test view_test jitter_test wire_test_ubsan
	rm -rf *.dSYM

.PHONY: all check clean

# ═════════════════════════════════════════════════════════════════════════════
# Adversarial suites (crypto / wire / view / jitter). Added as new rules only —
# the net_test and state_test rules above are untouched.
#
#   make check           net_test, state_test, crypto_test, wire_test, view_test
#   make check-jitter    jitter_test (slow: threads + 0-2 ms sleeps)
#   make TSAN=1 check-jitter      same, under ThreadSanitizer
#   ./crypto_test <seed> / ./wire_test <seed> / ...   replay an exact run
#
# Each test links the least it can: crypto_test touches only crypto.c and needs
# NO sqlite; wire_test/view_test/jitter_test pull state.o/view.o and so do.
# ═════════════════════════════════════════════════════════════════════════════
ifeq ($(TSAN),1)
SAN      := -fsanitize=thread -fno-omit-frame-pointer -g -O1
else
SAN      :=
endif
PTHREAD  := -lpthread

crypto_test: $(B)/crypto_test.o $(LIB) $(SECPLIB)
	$(CC) $(CFLAGS) $(SAN) -o $@ $< $(LIB) $(SECPLIB)

wire_test: $(B)/wire_test.o $(LIB) $(SECPLIB)
	$(CC) $(CFLAGS) $(SAN) -o $@ $< $(LIB) $(SECPLIB) $(SQLITE_LIBS)

view_test: $(B)/view_test.o $(LIB) $(SECPLIB)
	$(CC) $(CFLAGS) $(SAN) -o $@ $< $(LIB) $(SECPLIB) $(SQLITE_LIBS)

jitter_test: $(B)/jitter_test.o $(LIB) $(SECPLIB)
	$(CC) $(CFLAGS) $(SAN) -o $@ $< $(LIB) $(SECPLIB) $(SQLITE_LIBS) $(PTHREAD)

$(B)/crypto_test.o: test/crypto_test.c | $(B); $(CC) $(CFLAGS) $(SAN) $(INC) -c -o $@ $<
$(B)/wire_test.o:   test/wire_test.c   | $(B); $(CC) $(CFLAGS) $(SAN) $(INC) $(SQLITE_CFLAGS) -c -o $@ $<
$(B)/view_test.o:   test/view_test.c   | $(B); $(CC) $(CFLAGS) $(SAN) $(INC) $(SQLITE_CFLAGS) -c -o $@ $<
$(B)/jitter_test.o: test/jitter_test.c | $(B); $(CC) $(CFLAGS) $(SAN) $(INC) $(SQLITE_CFLAGS) -c -o $@ $<

check-jitter: jitter_test
	./jitter_test

# UBSan build of the LIBRARY (not just the test), into build/ubsan/. Use this
# when -fsanitize=address / =thread will not run: on macOS 26 / Apple clang 17
# (and Homebrew clang 20) the ASan and TSan runtimes abort before main — a bare
# `int main(){puts("hi");}` exits 137/139 — while UBSan works normally.
#   make check-ubsan     -> pins the exact file:line of any UB in the decoders
UB      := -fsanitize=undefined -fno-sanitize-recover=all -g -O1 -std=c11 -D_DEFAULT_SOURCE
UBDIR   := $(B)/ubsan
UBOBJ   := $(UBDIR)/wire.o $(UBDIR)/view.o $(UBDIR)/crypto.o $(UBDIR)/state.o \
           $(UBDIR)/sha256.o $(UBDIR)/ripemd160.o $(UBDIR)/secp_shim.o

$(UBDIR):
	mkdir -p $(UBDIR)

$(UBDIR)/wire.o:       src/wire.c        | $(UBDIR); $(CC) $(UB) $(INC) -c -o $@ $<
$(UBDIR)/view.o:       src/view.c        | $(UBDIR); $(CC) $(UB) $(INC) $(SQLITE_CFLAGS) -c -o $@ $<
$(UBDIR)/crypto.o:     src/crypto.c      | $(UBDIR); $(CC) $(UB) $(INC) $(INC_SM) -c -o $@ $<
$(UBDIR)/state.o:      src/state.c       | $(UBDIR); $(CC) $(UB) $(INC) $(SQLITE_CFLAGS) -c -o $@ $<
$(UBDIR)/sha256.o:     $(SMDIR)/sha256.c | $(UBDIR); $(CC) $(UB) $(INC_SM) -c -o $@ $<
$(UBDIR)/ripemd160.o:  $(SMDIR)/ripemd160.c | $(UBDIR); $(CC) $(UB) $(INC_SM) -c -o $@ $<
$(UBDIR)/secp_shim.o:  $(SHIMSRC)        | $(UBDIR); $(CC) $(UB) $(INC_SHIM) -c -o $@ $<

wire_test_ubsan: test/wire_test.c $(UBOBJ) $(SECPLIB)
	$(CC) $(UB) $(INC) $(SQLITE_CFLAGS) -o $@ $< $(UBOBJ) $(SECPLIB) $(SQLITE_LIBS)

check-ubsan: wire_test_ubsan
	./wire_test_ubsan

.PHONY: check-jitter check-ubsan
