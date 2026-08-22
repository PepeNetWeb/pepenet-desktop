# mk/webproxy.mk — the PAC + CONNECT browser front door (src/webproxy.c).
#
# Both suites compile src/webproxy.c ITSELF (unmodified) and satisfy its heavy
# dependencies with stubs defined inside the test file: ca_* / resolver_* /
# sscert_* / platform_* and, crucially, proxy_listen + proxy_serve_ctl. That
# keeps the link cheap — no libssl, no libcrypto, no sqlite, no secp, no
# Objective-C runtime — while leaving 100% of the front-door code under test
# real. Only the tls + openssl HEADERS are needed, for the opaque X509* /
# EVP_PKEY* / Resolver* types in webproxy.c's signatures; no OpenSSL symbol is
# referenced by webproxy.c, so $(LDLIBS) is deliberately NOT linked here.
#
#   t_webproxy — deterministic units: PAC bytes, request-parser robustness,
#                path handling, fd-leak sweep.  (make check)
#   j_webproxy — concurrency/jitter: N hammering clients, seeded random
#                timing, abrupt disconnects, start/stop races. (make check-jitter,
#                worth a `make TSAN=1 j_webproxy` run)
#
# j_webproxy prints its SplitMix64 seed; reproduce a failure with
# `./j_webproxy <seed>` or PEPE_JITTER_SEED=<seed>.
#
# NOTE (macOS 26.5 / arm64, Apple clang 17 and Homebrew LLVM 20/21): the
# ThreadSanitizer and AddressSanitizer runtimes are broken on this OS — a
# `int main(void){return 0;}` built with -fsanitize=thread dies instantly in
# __tsan::SlotLock with EXC_BAD_ACCESS, and the ASan one hangs at startup. Both
# `make TSAN=1 j_webproxy` and `make SAN=1 ...` therefore BUILD but cannot RUN
# here; retry on a machine with a working sanitizer runtime.

TESTS  += t_webproxy
JITTER += j_webproxy

WPINC  := -I$(TLSSRC) $(OPENSSL_INC)

t_webproxy: t_webproxy.c $(SRC)/webproxy.c
	$(CC) $(CFLAGS) $(INC) $(WPINC) -o $@ $^ $(LDFLAGS) -lpthread

j_webproxy: j_webproxy.c $(SRC)/webproxy.c
	$(CC) $(CFLAGS) $(INC) $(WPINC) -o $@ $^ $(LDFLAGS) -lpthread
