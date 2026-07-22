#!/usr/bin/env bash
# Build a macOS .icns from a single square PNG (>= 512x512 recommended).
# Usage: make_icns.sh <source.png> <out.icns>
set -euo pipefail

SRC="${1:?source png required}"
OUT="${2:?output icns required}"

if [[ ! -f "$SRC" ]]; then
    echo "make_icns: source not found: $SRC" >&2
    exit 1
fi

WORK="$(mktemp -d)"
ICONSET="$WORK/AppIcon.iconset"
mkdir -p "$ICONSET"
trap 'rm -rf "$WORK"' EXIT

# Standard iconset sizes (1x + 2x retina).
gen() { sips -z "$1" "$1" "$SRC" --out "$ICONSET/$2" >/dev/null; }
gen 16   icon_16x16.png
gen 32   icon_16x16@2x.png
gen 32   icon_32x32.png
gen 64   icon_32x32@2x.png
gen 128  icon_128x128.png
gen 256  icon_128x128@2x.png
gen 256  icon_256x256.png
gen 512  icon_256x256@2x.png
gen 512  icon_512x512.png
gen 1024 icon_512x512@2x.png

iconutil -c icns "$ICONSET" -o "$OUT"
echo "make_icns: wrote $OUT"
