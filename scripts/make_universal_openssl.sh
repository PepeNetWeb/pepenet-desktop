#!/usr/bin/env bash
# Build a universal (arm64 + x86_64) STATIC OpenSSL for the distributable app.
#
# Why not Homebrew: /opt/homebrew is arm64-only and Homebrew no longer ships
# x86_64 bottles at all — a universal pepenet.app needs both slices of
# libssl.a/libcrypto.a, version-identical, with the objects' Mach-O minimum
# matching the app's distribution floor (11.0), which only a source build
# guarantees. Output lands in vendor/openssl-universal/{include,lib}; the
# top-level CMakeLists prefers that prefix automatically when it exists.
#
#   scripts/make_universal_openssl.sh          # ~5-10 min, one-time
#   OPENSSL_VER=3.6.2 MACOS_MIN=11.0 ...       # overridable
set -euo pipefail

VER="${OPENSSL_VER:-3.6.2}"
MIN="${MACOS_MIN:-11.0}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/vendor/openssl-universal"
WORK="${TMPDIR:-/tmp}/openssl-universal-$VER"
URL="https://github.com/openssl/openssl/releases/download/openssl-$VER/openssl-$VER.tar.gz"

mkdir -p "$WORK"
cd "$WORK"
if [[ ! -f "openssl-$VER.tar.gz" ]]; then
    echo "==> Fetching openssl-$VER"
    curl -fsSLO "$URL"
fi

for ARCH in arm64 x86_64; do
    if [[ -f "$WORK/$ARCH/libssl.a" ]]; then
        echo "==> $ARCH already built"
        continue
    fi
    echo "==> Building $ARCH (min macOS $MIN)"
    rm -rf "src-$ARCH"
    mkdir "src-$ARCH"
    tar xzf "openssl-$VER.tar.gz" -C "src-$ARCH" --strip-components 1
    (
        cd "src-$ARCH"
        ./Configure "darwin64-$ARCH-cc" no-shared no-tests \
            -mmacosx-version-min="$MIN" >/dev/null
        make -j"$(sysctl -n hw.ncpu)" build_libs >/dev/null
    )
    mkdir -p "$ARCH"
    cp "src-$ARCH/libssl.a" "src-$ARCH/libcrypto.a" "$ARCH/"
done

echo "==> Merging into $OUT"
rm -rf "$OUT"
mkdir -p "$OUT/lib"
lipo -create arm64/libssl.a    x86_64/libssl.a    -output "$OUT/lib/libssl.a"
lipo -create arm64/libcrypto.a x86_64/libcrypto.a -output "$OUT/lib/libcrypto.a"
# headers: source tree + the build-generated ones (both darwin64 targets are
# LP64 — the generated configuration is identical across the two slices)
cp -R "src-arm64/include" "$OUT/include-stage"
mkdir -p "$OUT/include"
cp -R "$OUT/include-stage/openssl" "$OUT/include/openssl"
rm -rf "$OUT/include-stage"
rm -rf "src-arm64" "src-x86_64"

lipo -archs "$OUT/lib/libssl.a"
lipo -archs "$OUT/lib/libcrypto.a"
echo "Done: $OUT (openssl $VER, min macOS $MIN)"
