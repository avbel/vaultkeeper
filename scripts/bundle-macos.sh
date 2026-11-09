#!/usr/bin/env bash
# Builds target/bundle/Vaultkeeper.app for Apple silicon.
#
# Signing: uses the identity named by VAULTKEEPER_SIGN_IDENTITY (default "vaultkeeper local", created by
# scripts/make-signing-cert.sh) when it exists, otherwise an ad-hoc signature. A stable identity
# keeps keychain items (refresh token) readable across rebuilds without "allow access" prompts;
# with ad-hoc signing every rebuild is a new code identity.
#
# Both signatures use the hardened runtime (`--options runtime`) with no entitlements: dyld then
# ignores DYLD_* variables and library validation refuses dylibs signed by anyone else, so another
# process of this user cannot run the bundled binary with injected code. That matters because the
# daemon admits a UI process by its code signature (cdhash), see crates/ipc/src/peer.rs.
set -euo pipefail

cd "$(dirname "$0")/.."
TARGET=aarch64-apple-darwin
IDENTITY="${VAULTKEEPER_SIGN_IDENTITY:-vaultkeeper local}"
OUT=target/bundle
APP="$OUT/Vaultkeeper.app"
VERSION=$(cargo metadata --no-deps --format-version 1 \
  | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"]=="vaultkeeper"))')

rustup target add "$TARGET" >/dev/null
cargo build --release --locked --target "$TARGET" -p vaultkeeper

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "${CARGO_TARGET_DIR:-target}/$TARGET/release/vaultkeeper" "$APP/Contents/MacOS/vaultkeeper"
sed "s/@VERSION@/$VERSION/g" packaging/macos/Info.plist > "$APP/Contents/Info.plist"

if command -v rsvg-convert >/dev/null && command -v iconutil >/dev/null; then
  ICONSET=$(mktemp -d)/AppIcon.iconset
  mkdir -p "$ICONSET"
  for size in 16 32 128 256 512; do
    rsvg-convert -w "$size" -h "$size" packaging/macos/icon.svg -o "$ICONSET/icon_${size}x${size}.png"
    rsvg-convert -w $((size * 2)) -h $((size * 2)) packaging/macos/icon.svg -o "$ICONSET/icon_${size}x${size}@2x.png"
  done
  iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"
else
  echo "rsvg-convert not found: bundle has no app icon (brew install librsvg)" >&2
fi

if security find-identity -v -p codesigning | grep -q "\"$IDENTITY\""; then
  codesign --force --options runtime --sign "$IDENTITY" --identifier org.vaultkeeper.desktop "$APP"
  echo "signed with \"$IDENTITY\""
else
  codesign --force --options runtime --sign - --identifier org.vaultkeeper.desktop "$APP"
  echo "ad-hoc signed (run scripts/make-signing-cert.sh once for a stable identity)"
fi
codesign --verify --strict "$APP"
SIGNATURE=$(codesign --display --verbose "$APP" 2>&1)
if [[ "$SIGNATURE" != *"flags="*"runtime"* ]]; then
  echo "the bundle is not signed with the hardened runtime" >&2
  exit 1
fi
echo "built $APP ($VERSION, $(lipo -archs "$APP/Contents/MacOS/vaultkeeper"))"
