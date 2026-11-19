#!/usr/bin/env bash
# Cross-language conformance runner.
#
# Every reference implementation regenerates the IDENTICAL action stream from a
# seed, folds it, and prints `input_digest=` + `state_digest=`. This script runs
# each available implementation over a (seed, count) matrix and asserts they all
# agree. On a mismatch it re-runs with --trace and reports the first divergent
# block, and whether the input_digest (generator/PRNG drift) or only the
# state_digest (fold drift) differs.
#
#   ./run-conformance.sh            # default matrix
#   ./run-conformance.sh 1000000    # add a big soak to the matrix
set -u
cd "$(dirname "$0")"

SEEDS=(1 42 1000 31337)
COUNTS=(1000 20000 100000)
[ $# -ge 1 ] && COUNTS+=("$1")

# ── how to invoke each impl: `run_<lang> random <seed> <count> [--trace N]` ───
have_c=0; have_py=0; have_ts=0; have_rust=0; have_go=0; have_cs=0; have_java=0

build_impls() {
    if [ -f impls/c/Makefile ]; then ( cd impls/c && make -s ) && have_c=1; fi
    if command -v python3 >/dev/null && [ -f impls/py/sm.py ]; then have_py=1; fi
    if command -v node >/dev/null && [ -f impls/ts/sm.ts ]; then have_ts=1; fi
    if [ -f impls/rust/Cargo.toml ]; then ( cd impls/rust && cargo build --release -q 2>/dev/null ) && have_rust=1; fi
    if [ -f impls/go/go.mod ]; then ( cd impls/go && go build -o sm . 2>/dev/null ) && have_go=1; fi
    if [ -f impls/csharp/sm.csproj ]; then ( cd impls/csharp && dotnet build -c Release -v q 2>/dev/null ) && have_cs=1; fi
    if command -v java >/dev/null && [ -f impls/java/Sm.java ]; then have_java=1; fi   # reference-tier (source-launch)
}
run_c()    { impls/c/sm "$@"; }
run_py()   { python3 impls/py/sm.py "$@"; }
run_ts()   { node impls/ts/sm.ts "$@"; }
run_rust() { impls/rust/target/release/sm "$@"; }
run_go()   { ( cd impls/go && ./sm "$@" ); }
run_cs()   { dotnet impls/csharp/bin/Release/*/sm.dll "$@"; }

digests() { "run_$1" random "$2" "$3" 2>/dev/null | grep -E '^(input|state)_digest=' | sort; }

build_impls
IMPLS=()
# The gen.c-pinned seed soak requires a draw-for-draw-identical generator. ALL six other impls — TS
# (impls/ts), Java (impls/java), Rust (impls/rust), Python (impls/py), Go (impls/go), and now C#
# (impls/csharp) — are INDEPENDENT reimplementations with their own generators, so they cannot
# reproduce the seed-goldens by construction; they cross-check in the "reference-impl conformance"
# section below instead. As of the 2026-06-29 C# clean-room promotion the gen.c seed soak is C-ONLY:
# it no longer cross-checks a second port but remains C's self-regression lock (frozen scenario/attrib
# goldens + properties/reorg/reorgfuzz/meta violation==0 + coverage; the 130-unit C selftest/UBSan run
# out-of-band). The cross-language guarantee now lives entirely in the seven-impl reference tier below.
for l in c; do eval "[ \$have_$l = 1 ]" && IMPLS+=("$l"); done
echo "seed-soak implementations: ${IMPLS[*]} (c-only self-regression: frozen goldens + invariants + coverage)"
echo "reference-tier implementations:$([ $have_c = 1 ] && echo ' c')$([ $have_py = 1 ] && echo ' py')$([ $have_ts = 1 ] && echo ' ts')$([ $have_java = 1 ] && echo ' java')$([ $have_rust = 1 ] && echo ' rust')$([ $have_go = 1 ] && echo ' go')$([ $have_cs = 1 ] && echo ' cs')"
[ ${#IMPLS[@]} -lt 1 ] && { echo "need the c reference for the seed soak (have ${#IMPLS[@]})"; exit 1; }

REF=${IMPLS[0]}; fails=0; checks=0
for sc in "${COUNTS[@]}"; do for sd in "${SEEDS[@]}"; do
    ref=$(digests "$REF" "$sd" "$sc")
    for impl in "${IMPLS[@]:1}"; do
        checks=$((checks+1))
        got=$(digests "$impl" "$sd" "$sc")
        if [ "$ref" = "$got" ]; then
            printf "  ok   %-5s vs %-5s  seed=%-6s count=%-8s\n" "$REF" "$impl" "$sd" "$sc"
        else
            fails=$((fails+1))
            printf "FAIL   %-5s vs %-5s  seed=%-6s count=%-8s\n" "$REF" "$impl" "$sd" "$sc"
            r_in=$(echo "$ref" | grep input); g_in=$(echo "$got" | grep input)
            [ "$r_in" = "$g_in" ] && echo "       input_digest agrees → FOLD drift" || echo "       input_digest differs → GENERATOR/PRNG drift"
            # localise: first divergent --trace checkpoint
            tb=$(( sc / 20 + 1 ))
            diff <("run_$REF" random "$sd" "$sc" --trace "$tb" 2>/dev/null | grep '^TRACE') \
                 <("run_$impl" random "$sd" "$sc" --trace "$tb" 2>/dev/null | grep '^TRACE') \
                 | head -4 | sed 's/^/       /'
        fi
    done
done; done

# ── directed conformance vectors (named adversarial scenarios + oracle/MTP) ───
echo "── scenario vectors (54 named adversarial cases + combined) ──"
# NOTE — as of the 2026-06-29 C# clean-room promotion the gen.c seed soak is C-ONLY: every former
# port (rust→py→go→cs) has been de-staled and PROMOTED to the independent reference tier below, so
# there is no second byte-identical port to cross-check and NO expected staleness FAILs remain. The
# soak self-regresses the c reference against its frozen goldens (scenario combined 301ce369…,
# attrib-scenario 9fb14077…) and asserts the properties/reorg/reorgfuzz/meta violation counts are 0
# and the generator/decode coverage is complete; the cross-impl `random`/`fuzz`/`bfuzz`/`attrib`
# comparison loops simply no-op with a single soak impl. The cross-language guarantee lives entirely
# in the seven-impl reference tier (c · py · ts · java · rust · go · cs).
# See SPEC-conformance.md §"Two conformance tiers" / §6 and SPEC-RATIONALE.md.
# Re-pinned 2026-07-09 after the divergence-fix vectors 55/55b/56/57/58 (was c6101c4c…).
GOLDEN_COMBINED=aca6749e79b7e6b582e1f5043693b7991fcc592f4df537461e09d6b9e451d347
ref_scen=$("run_$REF" scenario 2>/dev/null)
ref_comb=$(echo "$ref_scen" | awk '/^combined/{print $2}')
checks=$((checks+1))
if [ "$ref_comb" = "$GOLDEN_COMBINED" ]; then printf "  ok   %-5s scenario combined == frozen golden\n" "$REF"
else printf "FAIL   %-5s scenario combined=%s != golden\n" "$REF" "$ref_comb"; fails=$((fails+1)); fi
for impl in "${IMPLS[@]:1}"; do
    checks=$((checks+1)); s=$("run_$impl" scenario 2>/dev/null)
    if [ "$s" = "$ref_scen" ]; then printf "  ok   %-5s vs %-5s  scenario (all vectors)\n" "$REF" "$impl"
    else printf "FAIL   %-5s vs %-5s  scenario\n" "$REF" "$impl"; fails=$((fails+1)); diff <(echo "$ref_scen") <(echo "$s") | head -6 | sed 's/^/       /'; fi
done

# ── differential fuzz / property / reorg modes ────────────────────────────────
# Each is a self-contained generator (raw byte payloads → decode → fold for fuzz;
# the soak stream + invariant battery for properties; record-and-replay confluence
# for reorg). Cross-check the digest line(s) of every impl against REF, and assert
# the property/reorg violation counts are zero.
modedig() { "run_$1" "$2" "$3" "$4" 2>/dev/null | grep -E '_digest=' | sort; }
echo "── fuzz mode (byte-level decode + fold; seeds × counts) ──"
for sd in 1 42 1000 31337; do for sc in 2000 30000; do
    ref=$(modedig "$REF" fuzz "$sd" "$sc")
    for impl in "${IMPLS[@]:1}"; do
        checks=$((checks+1)); got=$(modedig "$impl" fuzz "$sd" "$sc")
        if [ "$ref" = "$got" ]; then printf "  ok   %-5s vs %-5s  fuzz seed=%-6s count=%-6s\n" "$REF" "$impl" "$sd" "$sc"
        else printf "FAIL   %-5s vs %-5s  fuzz seed=%-6s count=%-6s\n" "$REF" "$impl" "$sd" "$sc"; fails=$((fails+1)); diff <(echo "$ref") <(echo "$got") | head -4 | sed 's/^/       /'; fi
    done
done; done
echo "── properties mode (invariants + cross-language property_digest) ──"
for sd in 1 42 1000 31337; do
    ref=$(modedig "$REF" properties "$sd" 30000)
    rv=$("run_$REF" properties "$sd" 30000 2>/dev/null | awk -F= '/^violations=/{print $2}')
    checks=$((checks+1)); [ "$rv" = 0 ] && printf "  ok   %-5s properties seed=%-6s violations=0\n" "$REF" "$sd" || { printf "FAIL   %-5s properties seed=%s violations=%s\n" "$REF" "$sd" "$rv"; fails=$((fails+1)); }
    for impl in "${IMPLS[@]:1}"; do
        checks=$((checks+1)); got=$(modedig "$impl" properties "$sd" 30000)
        if [ "$ref" = "$got" ]; then printf "  ok   %-5s vs %-5s  properties seed=%-6s\n" "$REF" "$impl" "$sd"
        else printf "FAIL   %-5s vs %-5s  properties seed=%s\n" "$REF" "$impl" "$sd"; fails=$((fails+1)); diff <(echo "$ref") <(echo "$got") | head -4 | sed 's/^/       /'; fi
    done
done
echo "── reorg mode (replay / resume / clear-rebuild / fork confluence) ──"
for sd in 1 42 1000 31337; do
    ref=$(modedig "$REF" reorg "$sd" 6000)
    rf=$("run_$REF" reorg "$sd" 6000 2>/dev/null | awk '/^blocks=/{for(i=1;i<=NF;i++){split($i,a,"=");if(a[1]=="failures")print a[2]}}')
    checks=$((checks+1)); [ "$rf" = 0 ] && printf "  ok   %-5s reorg seed=%-6s failures=0\n" "$REF" "$sd" || { printf "FAIL   %-5s reorg seed=%s failures=%s\n" "$REF" "$sd" "$rf"; fails=$((fails+1)); }
    for impl in "${IMPLS[@]:1}"; do
        checks=$((checks+1)); got=$(modedig "$impl" reorg "$sd" 6000)
        if [ "$ref" = "$got" ]; then printf "  ok   %-5s vs %-5s  reorg seed=%-6s\n" "$REF" "$impl" "$sd"
        else printf "FAIL   %-5s vs %-5s  reorg seed=%s\n" "$REF" "$impl" "$sd"; fails=$((fails+1)); diff <(echo "$ref") <(echo "$got") | head -4 | sed 's/^/       /'; fi
    done
done
echo "── bfuzz mode (boundary-cluster fuzz: values snapped to §-constants) ──"
for sd in 1 42 1000 31337; do
    ref=$(modedig "$REF" bfuzz "$sd" 30000)
    for impl in "${IMPLS[@]:1}"; do
        checks=$((checks+1)); got=$(modedig "$impl" bfuzz "$sd" 30000)
        if [ "$ref" = "$got" ]; then printf "  ok   %-5s vs %-5s  bfuzz seed=%-6s\n" "$REF" "$impl" "$sd"
        else printf "FAIL   %-5s vs %-5s  bfuzz seed=%s\n" "$REF" "$impl" "$sd"; fails=$((fails+1)); diff <(echo "$ref") <(echo "$got") | head -4 | sed 's/^/       /'; fi
    done
done
echo "── reorgfuzz mode (64 PRNG fork/divergence trials per chain) ──"
for sd in 1 42 1000 31337; do
    ref=$(modedig "$REF" reorgfuzz "$sd" 6000)
    rf=$("run_$REF" reorgfuzz "$sd" 6000 2>/dev/null | awk '/^blocks=/{for(i=1;i<=NF;i++){split($i,a,"=");if(a[1]=="failures")print a[2]}}')
    checks=$((checks+1)); [ "$rf" = 0 ] && printf "  ok   %-5s reorgfuzz seed=%-6s failures=0\n" "$REF" "$sd" || { printf "FAIL   %-5s reorgfuzz seed=%s failures=%s\n" "$REF" "$sd" "$rf"; fails=$((fails+1)); }
    for impl in "${IMPLS[@]:1}"; do
        checks=$((checks+1)); got=$(modedig "$impl" reorgfuzz "$sd" 6000)
        if [ "$ref" = "$got" ]; then printf "  ok   %-5s vs %-5s  reorgfuzz seed=%-6s\n" "$REF" "$impl" "$sd"
        else printf "FAIL   %-5s vs %-5s  reorgfuzz seed=%s\n" "$REF" "$impl" "$sd"; fails=$((fails+1)); diff <(echo "$ref") <(echo "$got") | head -4 | sed 's/^/       /'; fi
    done
done
echo "── meta mode (metamorphic drop-closed: inert actions stay inert) ──"
for sd in 1 42 1000 31337; do
    ref=$(modedig "$REF" meta "$sd" 15000)
    rf=$("run_$REF" meta "$sd" 15000 2>/dev/null | awk '/^blocks=/{for(i=1;i<=NF;i++){split($i,a,"=");if(a[1]=="failures")print a[2]}}')
    checks=$((checks+1)); [ "$rf" = 0 ] && printf "  ok   %-5s meta seed=%-6s failures=0\n" "$REF" "$sd" || { printf "FAIL   %-5s meta seed=%s failures=%s\n" "$REF" "$sd" "$rf"; fails=$((fails+1)); }
    for impl in "${IMPLS[@]:1}"; do
        checks=$((checks+1)); got=$(modedig "$impl" meta "$sd" 15000)
        if [ "$ref" = "$got" ]; then printf "  ok   %-5s vs %-5s  meta seed=%-6s\n" "$REF" "$impl" "$sd"
        else printf "FAIL   %-5s vs %-5s  meta seed=%s\n" "$REF" "$impl" "$sd"; fails=$((fails+1)); diff <(echo "$ref") <(echo "$got") | head -4 | sed 's/^/       /'; fi
    done
done
# generator/decode coverage assertion (C meta-test: every branch the soak + fuzzer
# is meant to reach actually fires). Generators are pinned identical across langs, so
# one run on the reference impl certifies all.
if [ $have_c = 1 ]; then
    echo "── coverage assertion (every generator + decode branch exercised) ──"
    checks=$((checks+1)); cov=$(impls/c/sm coverage 42 300000 2>/dev/null | awk '/^coverage:/{print $2}')
    [ "$cov" = 0 ] && printf "  ok   c     coverage: 0 uncovered branches\n" || { printf "FAIL   c     coverage: %s uncovered\n" "$cov"; fails=$((fails+1)); impls/c/sm coverage 42 300000 2>/dev/null | grep UNCOVERED | sed 's/^/       /'; }
fi

# ── §4 attribution shell (raw tx bytes → {Identity|drop}; injected curve verdict) ──
# A separate seed-driven layer: strict-DER / low-S / pubkey-encoding / P2SH-multisig
# template + in-order scan / legacy sighash incl. FindAndDelete / RIPEMD160 identity,
# computed for real; only ecdsa_verify + on_curve are injected (pinned pseudo-funcs).
echo "── attrib mode (§4 byte-logic shell: raw tx → Identity|drop) ──"
ATTRIB_GOLDEN=9fb140772fc746863100d4a88379b91f362ef011735fcb68ed4210b095c238f8
for sd in 1 42 1000 31337; do for sc in 2000 50000; do
    ref=$(modedig "$REF" attrib "$sd" "$sc")
    for impl in "${IMPLS[@]:1}"; do
        checks=$((checks+1)); got=$(modedig "$impl" attrib "$sd" "$sc")
        if [ "$ref" = "$got" ]; then printf "  ok   %-5s vs %-5s  attrib seed=%-6s count=%-6s\n" "$REF" "$impl" "$sd" "$sc"
        else printf "FAIL   %-5s vs %-5s  attrib seed=%-6s count=%-6s\n" "$REF" "$impl" "$sd" "$sc"; fails=$((fails+1)); diff <(echo "$ref") <(echo "$got") | head -4 | sed 's/^/       /'; fi
    done
done; done
echo "── attrib-scenario (RIPEMD160 KAT + named vectors + combined) ──"
ref_attr=$("run_$REF" attrib-scenario 2>/dev/null)
ref_acomb=$(echo "$ref_attr" | awk '/^combined/{print $2}')
checks=$((checks+1))
if [ "$ref_acomb" = "$ATTRIB_GOLDEN" ]; then printf "  ok   %-5s attrib-scenario combined == frozen golden\n" "$REF"
else printf "FAIL   %-5s attrib-scenario combined=%s != golden\n" "$REF" "$ref_acomb"; fails=$((fails+1)); fi
for impl in "${IMPLS[@]:1}"; do
    checks=$((checks+1)); s=$("run_$impl" attrib-scenario 2>/dev/null)
    if [ "$s" = "$ref_attr" ]; then printf "  ok   %-5s vs %-5s  attrib-scenario (all vectors)\n" "$REF" "$impl"
    else printf "FAIL   %-5s vs %-5s  attrib-scenario\n" "$REF" "$impl"; fails=$((fails+1)); diff <(echo "$ref_attr") <(echo "$s") | head -6 | sed 's/^/       /'; fi
done

# ── reference-impl conformance (independent reimplementations: C · Python · Java · TS · Rust · Go · C#) ──
# C (production reference), Python, Java, TS, Rust, Go, and C# (the latter six clean-room, each built
# from prose alone) are INDEPENDENT implementations. They cannot share the gen.c-pinned seed soak, so
# they cross-validate on the PROSE-PINNED surface: the consensus-fork differential vectors (TV-1..TV-8
# + M9), each impl independently producing the spec-mandated outcome. Seven independent impls agreeing
# on every fork vector is the strongest consensus-correctness signal. See SPEC-conformance.md §"Two tiers".
echo "── reference-impl fork-vector conformance (independent: c · py · ts · java · rust · go · cs) ──"
ref_fv() {  # $1=label  $2..=command; PASS iff the tail reports "<n> match/pass, 0 diverge/fail"
    checks=$((checks+1))
    out=$("${@:2}" 2>/dev/null)
    if echo "$out" | grep -qE '[0-9]+ (match|pass), 0 (diverge|fail)'; then
        printf "  ok   %-20s %s\n" "$1" "$(echo "$out" | grep -oE '[0-9]+ (match|pass), [0-9]+ (diverge|fail)' | tail -1)"
    else
        printf "FAIL   %-20s\n" "$1"; fails=$((fails+1)); echo "$out" | tail -3 | sed 's/^/       /'
    fi
}
[ $have_c    = 1 ] && ref_fv "c    forkvectors"   impls/c/sm forkvectors
[ $have_py   = 1 ] && ref_fv "py   forkvectors"   python3 impls/py/sm.py forkvectors
[ $have_ts   = 1 ] && ref_fv "ts   forkvectors"   node impls/ts/sm.ts forkvectors
[ $have_java = 1 ] && ref_fv "java behav (TV+M9)" java impls/java/Sm.java behav
[ $have_rust = 1 ] && ref_fv "rust forkvectors"  impls/rust/target/release/sm forkvectors
[ $have_go   = 1 ] && ref_fv "go   forkvectors"  run_go forkvectors
[ $have_cs   = 1 ] && ref_fv "cs   forkvectors"  run_cs forkvectors

# ── §4 Strategy B: real-secp256k1 curve-vector conformance (independent: c·py·ts·java·rust·go·cs) ──
# `attrib-curve` runs the pinned ECDSA curve-vector set against each impl's OWN self-rolled
# secp256k1: pinned P/N/N_HALF constants, on-curve membership at the edges, RFC-6979
# deterministic (r,s)+canonical-DER known-answers, ECDSA verify at the scalar boundaries
# (r/s=0,n; tampered hash; wrong key; high-S still verifies), the priv=1⇒G / priv=2⇒2G
# tiny-key KAT (an EXTERNAL anchor — universal truths), and the end-to-end sighash→verify
# pipeline (sign the real legacy sighash, attribute() with the real curve). Output is
# byte-identical across all 7 impls and carries two frozen digests: `combined` (the pure
# curve layer) and `combined_e2e` (the attribution pipeline). Seven independent self-rolled
# curves agreeing on every accept/reject bit + every (r,s) is the evidence the curve is real.
echo "── attrib-curve: real secp256k1 vector set (independent: c · py · ts · java · rust · go · cs) ──"
CURVE_GOLDEN=5b7d1e765c7a213bab6825abf1fb75fc6c9fa0771c7b58484cc0d2a3b2bf7113
CURVE_E2E_GOLDEN=c24c560202f6a8cf6a154ce54cdfe80ee32dc440d1c9594124c7939c62d54a14
curve_run() { case "$1" in
    c)    impls/c/sm attrib-curve ;;            py)   python3 impls/py/sm.py attrib-curve ;;
    ts)   node impls/ts/sm.ts attrib-curve ;;   java) java impls/java/Sm.java attrib-curve ;;
    rust) impls/rust/target/release/sm attrib-curve ;; go) run_go attrib-curve ;; cs) run_cs attrib-curve ;;
  esac ; }
if [ $have_c = 1 ]; then
    ref_curve=$(curve_run c 2>/dev/null)
    rc=$(echo "$ref_curve" | awk '/^combined /{print $2}'); re=$(echo "$ref_curve" | awk '/^combined_e2e /{print $2}')
    checks=$((checks+1))
    if [ "$rc" = "$CURVE_GOLDEN" ] && [ "$re" = "$CURVE_E2E_GOLDEN" ]; then
        printf "  ok   c     attrib-curve combined + combined_e2e == frozen goldens\n"
    else printf "FAIL   c     attrib-curve combined=%s e2e=%s != goldens\n" "$rc" "$re"; fails=$((fails+1)); fi
    for impl in py ts java rust go cs; do
        eval "[ \$have_$impl = 1 ]" || continue
        checks=$((checks+1)); got=$(curve_run "$impl" 2>/dev/null)
        if [ "$got" = "$ref_curve" ]; then printf "  ok   %-5s vs c    attrib-curve (all vectors byte-identical)\n" "$impl"
        else printf "FAIL   %-5s vs c    attrib-curve\n" "$impl"; fails=$((fails+1)); diff <(echo "$ref_curve") <(echo "$got") | head -8 | sed 's/^/       /'; fi
    done
fi

# ── §13.2: ECMH incremental state-digest vector set (independent: c·py·ts·java·rust·go·cs) ──
# `ecmh` runs the pinned ECMH primitive script against each impl's OWN secp256k1 + hash-to-curve:
# the try-and-increment H2C KATs (fixed preimages → ctr + even-Y compressed point), the ∞ identity,
# and a tagged multiset sum proven order-independent (commutative) and invertible (remove + re-add
# round-trips to the same accumulator) — all folded into one `combined` digest. Byte-identical
# across all 7 impls: this is the incremental state digest a node maintains in O(rows-changed)/block
# to detect desync against peers (and the harness uses to detect an impl diverging). §13.2.
echo "── ecmh: ECMH state-digest vector set (independent: c · py · ts · java · rust · go · cs) ──"
# Re-pinned 2026-07-08: KAT set dropped TAG_VOTE (names-only).
ECMH_GOLDEN=9acf22fd59d63a42791d6a57c68c397ec8e8e661b901bc1d2f1d1ada673a41e0
ecmh_run() { case "$1" in
    c)    impls/c/sm ecmh ;;                    py)   python3 impls/py/sm.py ecmh ;;
    ts)   node impls/ts/sm.ts ecmh ;;           java) java impls/java/Sm.java ecmh ;;
    rust) impls/rust/target/release/sm ecmh ;;  go)   run_go ecmh ;; cs) run_cs ecmh ;;
  esac ; }
if [ $have_c = 1 ]; then
    ref_ecmh=$(ecmh_run c 2>/dev/null)
    rh=$(echo "$ref_ecmh" | awk '/^combined /{print $2}')
    checks=$((checks+1))
    if [ "$rh" = "$ECMH_GOLDEN" ]; then printf "  ok   c     ecmh combined == frozen golden\n"
    else printf "FAIL   c     ecmh combined=%s != golden\n" "$rh"; fails=$((fails+1)); fi
    for impl in py ts java rust go cs; do
        eval "[ \$have_$impl = 1 ]" || continue
        checks=$((checks+1)); got=$(ecmh_run "$impl" 2>/dev/null)
        if [ "$got" = "$ref_ecmh" ]; then printf "  ok   %-5s vs c    ecmh (all vectors byte-identical)\n" "$impl"
        else printf "FAIL   %-5s vs c    ecmh\n" "$impl"; fails=$((fails+1)); diff <(echo "$ref_ecmh") <(echo "$got") | head -8 | sed 's/^/       /'; fi
    done
fi

# ── ECMH state-digest anchor: every impl's sm_state_ecmh(empty) agrees (independent) ──
# The `ecmh` mode above pins the ECMH *primitive*; this pins the *state binding* — each impl's
# sm_state_ecmh over the EMPTY state is a fixed value (all five sub-accumulators = ∞), so every
# impl printing the same `empty_state_ecmh=` in its selftest proves the per-table tagging + the
# top-level combine agree across languages (not just the curve math). §13.2.
echo "── ecmh state anchor: sm_state_ecmh(empty) byte-identical (independent: c · py · ts · java · rust · go · cs) ──"
# Re-pinned 2026-07-08: empty state is names+commits+muts only (3 ECMH tables).
ECMH_STATE_ANCHOR=3ecfc3d7fa5be56fc513dde926bdf105c92accbf07088e702f85856fa69d10e0
anchor_run() { case "$1" in
    c)    impls/c/sm selftest ;;                py)   python3 impls/py/sm.py selftest ;;
    ts)   node impls/ts/sm.ts selftest ;;       java) java impls/java/Sm.java selftest ;;
    rust) impls/rust/target/release/sm selftest ;; go) run_go selftest ;; cs) run_cs selftest ;;
  esac ; }
for impl in c py ts java rust go cs; do
    eval "[ \$have_$impl = 1 ]" || continue
    checks=$((checks+1))
    a=$(anchor_run "$impl" 2>/dev/null | awk -F= '/^empty_state_ecmh=/{print $2}')
    if [ "$a" = "$ECMH_STATE_ANCHOR" ]; then printf "  ok   %-5s empty_state_ecmh == anchor\n" "$impl"
    else printf "FAIL   %-5s empty_state_ecmh=%s != anchor\n" "$impl" "$a"; fails=$((fails+1)); fi
done

# ── reference-tier self-validation: hand-authored selftest battery (all 7 impls) ──
# Every independent impl ships its OWN unit battery (RIPEMD/SHA/digest KATs, per-opcode
# fold cases, attribution incl. the A7 off-curve-P2PKH regression). These are
# generator-independent — they run on every impl regardless of soak parity — and each
# self-aborts (non-zero exit) on any failed check, so PASS keys on the exit status.
echo "── reference-impl selftest batteries (independent unit vectors, all 7 impls) ──"
ref_self() {  # $1=label  $2..=command; PASS iff the command exits 0
    checks=$((checks+1))
    if out=$("${@:2}" 2>&1); then
        printf "  ok   %-24s %s\n" "$1" "$(echo "$out" | grep -oiE 'ALL PASS|selftest: [0-9]+ (passed|pass)|self-test: [0-9]+ checks|(violations|failures|parser_crashes)=[0-9]+|[0-9]+ pass' | tr '\n' ' ' | head -c 64)"
    else
        printf "FAIL   %-24s\n" "$1"; fails=$((fails+1)); echo "$out" | tail -4 | sed 's/^/       /'
    fi
}
[ $have_c    = 1 ] && ref_self "c    selftest"  impls/c/sm selftest
[ $have_py   = 1 ] && ref_self "py   selftest"  python3 impls/py/sm.py selftest
[ $have_ts   = 1 ] && ref_self "ts   selftest"  node impls/ts/sm.ts selftest
[ $have_java = 1 ] && ref_self "java selftest"  java impls/java/Sm.java selftest
[ $have_rust = 1 ] && ref_self "rust selftest"  impls/rust/target/release/sm selftest
[ $have_go   = 1 ] && ref_self "go   selftest"  run_go selftest
[ $have_cs   = 1 ] && ref_self "cs   selftest"  run_cs selftest

# ── reference-tier §8/§9/§10/§11 invariant batteries on EVERY independent fold ──
# These are generator-INDEPENDENT: every correct fold must preserve them on ANY action
# stream, so a digest match is neither expected nor required (each impl drives its OWN
# generator). What is asserted is the violation/failure/crash COUNT == 0:
#   properties  — §8 fold invariants (lease bounds, market relations, mut height, no overflow)
#   reorg       — §10 confluence: replay / resume / clear-rebuild / fork-and-return
#   reorgfuzz   — §10 confluence under K=64 PRNG-chosen fork/divergence trials
#   meta        — §11 inert-action inertness (an op the protocol ignores leaves the digest fixed)
#   fuzz        — §9 decoder crash-safety over random + grammar-perturbed OP_RETURN bytes
# The c reference asserts these in the Tier-1 soak above. Each of the six other independent
# folds (py·ts·java·rust·go·cs) now re-asserts the same invariants on its OWN generated
# chain across four seeds — so all SEVEN unrelated folds certify the protocol invariants
# over seven unrelated streams. Each impl self-aborts (non-zero exit) on any nonzero count,
# so PASS keys on the exit status. (This broad run is what first surfaced the impls/py
# under-length-bitmap fail-loud divergence — now aligned to the C normative bit_set bound.)
inv_cmd() {  # echo the per-impl invocation prefix for the invariant modes
    case "$1" in
        py)   echo "python3 impls/py/sm.py" ;;
        ts)   echo "node impls/ts/sm.ts" ;;
        java) echo "java impls/java/Sm.java" ;;
        rust) echo "impls/rust/target/release/sm" ;;
        go)   echo "run_go" ;;
        cs)   echo "run_cs" ;;
    esac
}
echo "── independent-fold invariant batteries: §8 properties · §10 reorg/reorgfuzz · §11 meta · §9 fuzz (6 impls × 4 seeds) ──"
for impl in py ts java rust go cs; do
    eval "[ \$have_$impl = 1 ]" || continue
    cmd=$(inv_cmd "$impl")
    for sd in 1 42 1000 31337; do
        ref_self "$impl properties s=$sd" $cmd properties "$sd" 30000
        ref_self "$impl reorg s=$sd"      $cmd reorg "$sd" 6000
        ref_self "$impl meta s=$sd"       $cmd meta "$sd" 15000
        ref_self "$impl reorgfuzz s=$sd"  $cmd reorgfuzz "$sd" 6000
        ref_self "$impl fuzz s=$sd"       $cmd fuzz "$sd" 30000
    done
done

echo "────────────────────────────────────────────────────────"
echo "$checks cross-checks, $fails failure(s)"
echo "  seed-soak (Tier 1): ${IMPLS[*]} — c-only self-regression (goldens + invariants + coverage)"
echo "  reference  (Tier 2): c py ts java rust go cs — forkvectors + selftest ×7; §8/§9/§10/§11 invariant batteries on all 7 folds"
echo "  curve (§4 Strategy B): c py ts java rust go cs — real secp256k1 attrib-curve byte-identical (combined + combined_e2e frozen)"
echo "  ecmh (§13.2): c py ts java rust go cs — incremental ECMH state digest byte-identical (combined frozen)"
exit $([ $fails -eq 0 ] && echo 0 || echo 1)
