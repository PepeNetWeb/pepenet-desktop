#!/bin/sh
set -e
cd "$(dirname "$0")/.."

# ── Git submodules: pinned upstreams (not curl-from-master) ───────────────────
# sokol, nuklear (+ later wallet-milestone pins: cJSON, qrcodegen) are git
# submodules pinned to exact commits. Init whichever are recorded in .gitmodules;
# this is a no-op once they're present. (libsecp256k1 rides the indexer's pin.)
if [ -d .git ] || [ -f .git ]; then
    echo "Initializing git submodules..."
    for sub in vendor/sokol vendor/nuklear vendor/cjson vendor/qrcodegen; do
        git config -f .gitmodules "submodule.$sub.url" >/dev/null 2>&1 && \
            git submodule update --init "$sub"
    done
else
    echo "  (submodules missing and not a git checkout — re-clone with --recurse-submodules)"
fi

# ── curl single files (extracted/generated from huge upstream monorepos, so not
#    worth a submodule) ─────────────────────────────────────────────────────────

# UI typefaces (docs/gui-design-prompt.md): Patrick Hand (voice), Space Mono
# (truth — every amount/address/countdown), Noto Emoji (monochrome, flat).
FONT_DIR=vendor/fonts
mkdir -p "$FONT_DIR"
fetch_font() { # $1 = dest file, $2 = URL
    if [ ! -f "$FONT_DIR/$1" ]; then
        echo "Fetching $1..."
        curl -fsSL "$2" -o "$FONT_DIR/$1" || echo "  (skipped — $1 will fall back)"
    fi
}
fetch_font PatrickHand-Regular.ttf \
    "https://raw.githubusercontent.com/google/fonts/main/ofl/patrickhand/PatrickHand-Regular.ttf"
fetch_font SpaceMono-Regular.ttf \
    "https://raw.githubusercontent.com/google/fonts/main/ofl/spacemono/SpaceMono-Regular.ttf"
fetch_font SpaceMono-Bold.ttf \
    "https://raw.githubusercontent.com/google/fonts/main/ofl/spacemono/SpaceMono-Bold.ttf"
fetch_font NotoEmoji-Regular.ttf \
    "https://raw.githubusercontent.com/google/fonts/main/ofl/notoemoji/NotoEmoji%5Bwght%5D.ttf"

# BIP39 English wordlist -> C header
BIP39_DIR=vendor/bip39
if [ ! -f "$BIP39_DIR/wordlist.h" ]; then
    echo "Fetching BIP39 wordlist..."
    mkdir -p "$BIP39_DIR"
    curl -fsSL "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt" \
         -o "$BIP39_DIR/english.txt"
    awk 'BEGIN { print "// Generated from bip-0039/english.txt"; \
                 print "static const char *BIP39_WORDS[2048] = {" } \
         { printf "\"%s\",", $1 } \
         END { print "\n};" }' "$BIP39_DIR/english.txt" > "$BIP39_DIR/wordlist.h"
fi

echo "Done."
