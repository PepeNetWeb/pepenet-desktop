#!/usr/bin/env bash
# Build pepenet and wrap it in a distributable tarball.
#
#   packaging/package-linux.sh
#
# Output: dist/pepenet-<version>-linux-<arch>.tar.gz
# containing bin/pepenet, resources/, and a .desktop.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build-linux"
DIST="$ROOT/dist"
VERSION="$(sed -n 's/^set(PEPENET_VERSION "\([^"]*\)").*/\1/p' "$ROOT/CMakeLists.txt")"
[[ -n "$VERSION" ]] || { echo "error: PEPENET_VERSION not found in CMakeLists.txt" >&2; exit 1; }
ARCH="$(uname -m)"
STAGE="$DIST/pepenet-$VERSION-linux-$ARCH"

echo "==> Configuring (Release)"
cmake -S "$ROOT" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release

echo "==> Building"
cmake --build "$BUILD" --target pepenet-desktop --config Release -j

BIN="$BUILD/pepenet"
[[ -x "$BIN" ]] || { echo "error: $BIN not found" >&2; exit 1; }

echo "==> Staging"
rm -rf "$STAGE"
mkdir -p "$STAGE/bin" "$STAGE/resources"
cp "$BIN" "$STAGE/bin/pepenet"
cp -R "$BUILD/resources/." "$STAGE/resources/" 2>/dev/null || true
# fonts + helper + tray are copied by the POST_BUILD rule; copy the desktop file
# next to the binary's resources and also at the tarball root for xdg installers
cp "$ROOT/packaging/pepenet.desktop" "$STAGE/pepenet.desktop"
cp "$ROOT/packaging/pepenet-tray.png" "$STAGE/resources/pepenet-tray.png"
chmod +x "$STAGE/bin/pepenet" "$STAGE/resources/install-helper-linux.sh" 2>/dev/null || true

echo "==> Tarball"
mkdir -p "$DIST"
tar -C "$DIST" -czf "$DIST/pepenet-$VERSION-linux-$ARCH.tar.gz" "pepenet-$VERSION-linux-$ARCH"
echo "wrote $DIST/pepenet-$VERSION-linux-$ARCH.tar.gz"
