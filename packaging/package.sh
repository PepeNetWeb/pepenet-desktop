#!/usr/bin/env bash
# Build pepenet-desktop.app (PepeNet) and wrap it in a distributable .dmg.
#
#   packaging/package.sh                 # ad-hoc signed (default)
#   CODESIGN_ID="Developer ID Application: You (TEAMID)" packaging/package.sh
#
# With a Developer ID set, the .app is signed with the hardened runtime so it can
# be notarized (see the notarize step at the bottom, commented out). Without one,
# it falls back to an ad-hoc signature: the app runs locally, but other users must
# right-click > Open (or `xattr -dr com.apple.quarantine`) the first time.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build"
DIST="$ROOT/dist"
APP_NAME="pepenet-desktop"   # CMake target
BUNDLE="pepenet"             # OUTPUT_NAME → pepenet.app (CMakeLists)
VERSION="0.1.0"
CODESIGN_ID="${CODESIGN_ID:-}"

echo "==> Configuring (Release)"
cmake -S "$ROOT" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release >/dev/null

echo "==> Building"
cmake --build "$BUILD" --target "$APP_NAME" --config Release -j

APP="$BUILD/$BUNDLE.app"
[[ -d "$APP" ]] || { echo "error: $APP not found" >&2; exit 1; }

echo "==> Signing"
# NO keychain-access-groups entitlement. It reads as harmless ("let the app
# into its own keychain group") but it is a RESTRICTED entitlement: on a
# Developer ID app distributed outside the App Store, claiming it requires an
# embedded provisioning profile that authorizes it. We have no such profile, so
# AMFI refuses the launch — the app dies at spawn with the opaque "Launchd job
# spawn failed" (RBSRequestErrorDomain 5 / POSIX 163), no crash report, no log.
# (Verified by bisection: DevID+hardened launches; add this entitlement → killed.)
# And it buys nothing: its value <teamID>.<bundleID> is EXACTLY the default
# keychain access group every signed app already gets implicitly, so the wallet
# key add/read is silent under the stable Developer ID identity without it. If a
# future build genuinely needs to SHARE a keychain group across apps, the fix is
# to embed a provisioning profile that grants the group — not to sign it bare.
if [[ -n "$CODESIGN_ID" ]]; then
    codesign --force --deep --options runtime --timestamp --sign "$CODESIGN_ID" "$APP"
else
    # Ad-hoc: unsigned identity, so keychain items' ACL can't trust a stable
    # signature — macOS prompts once per launch to allow wallet-key access.
    codesign --force --deep --sign - "$APP"
fi
codesign --verify --verbose "$APP" || true

echo "==> Staging .dmg contents"
rm -rf "$DIST"
mkdir -p "$DIST/stage"
cp -R "$APP" "$DIST/stage/"
ln -s /Applications "$DIST/stage/Applications"

DMG="$DIST/$BUNDLE-$VERSION.dmg"
echo "==> Building $DMG"
hdiutil create \
    -volname "$BUNDLE" \
    -srcfolder "$DIST/stage" \
    -ov -format UDZO \
    "$DMG" >/dev/null
rm -rf "$DIST/stage"

# Sign the DMG container too (the app inside is already signed): without this,
# `spctl -t open` sees "no usable signature" on the disk image itself — the
# stapled ticket still validates, but a signed container is the clean story.
if [[ -n "$CODESIGN_ID" ]]; then
    codesign --force --timestamp --sign "$CODESIGN_ID" "$DMG"
fi

echo
echo "Done: $DMG"
echo "Bundle: $APP"
if [[ -z "$CODESIGN_ID" ]]; then
    echo
    echo "Note: ad-hoc signed. First launch on another Mac:"
    echo "      right-click the app > Open, or run:"
    echo "      xattr -dr com.apple.quarantine /Applications/$BUNDLE.app"
fi

# ── Notarization (requires a Developer ID + notarytool credentials) ───────────
# One-time credential setup (uses an app-specific password from appleid.apple.com):
#   xcrun notarytool store-credentials pepenet-notary \
#       --apple-id you@example.com --team-id TEAMID --password APP_SPECIFIC_PW
# Then, with CODESIGN_ID set to the Developer ID Application identity, run with
# NOTARIZE=1 to submit + staple:
if [[ -n "$CODESIGN_ID" && "${NOTARIZE:-}" == "1" ]]; then
    echo "==> Notarizing"
    xcrun notarytool submit "$DMG" --keychain-profile pepenet-notary --wait
    xcrun stapler staple "$DMG"
fi
