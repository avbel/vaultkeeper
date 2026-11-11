#!/usr/bin/env bash
# Builds target/kit/Vaultkeeper-kit-<version>.zip: the app bundle, the unpacked Chrome extension, an installer and a guide
# for installing on another Apple-silicon Mac. Pass --no-build to reuse target/bundle and browsers/release.
set -euo pipefail

cd "$(dirname "$0")/.."
VERSION=$(cargo metadata --no-deps --format-version 1 \
  | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"]=="vaultkeeper"))')
EXT_VERSION=$(python3 -c 'import json; print(json.load(open("browsers/package.json"))["version"])')
CHROME_ZIP="browsers/release/vaultkeeper-chrome-$EXT_VERSION.zip"
FIREFOX_XPI="browsers/release/vaultkeeper-firefox-$EXT_VERSION.xpi"

if [ "${1:-}" != "--no-build" ]; then
  scripts/bundle-macos.sh
  (cd browsers && pnpm install --frozen-lockfile && pnpm run package)
fi
[ -d target/bundle/Vaultkeeper.app ] || { echo "missing target/bundle/Vaultkeeper.app" >&2; exit 1; }
[ -f "$CHROME_ZIP" ] || { echo "missing $CHROME_ZIP" >&2; exit 1; }

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
KIT="$STAGE/Vaultkeeper-kit"
mkdir -p "$KIT/chrome-extension"
ditto target/bundle/Vaultkeeper.app "$KIT/Vaultkeeper.app"
unzip -q "$CHROME_ZIP" -d "$KIT/chrome-extension"
# The signed add-on comes from `pnpm sign:firefox`, which needs AMO credentials, so it is optional here.
if [ -f "$FIREFOX_XPI" ]; then
  cp "$FIREFOX_XPI" "$KIT/vaultkeeper-firefox.xpi"
fi
cp packaging/kit/install.command packaging/kit/uninstall.command packaging/kit/INSTALL.md "$KIT/"
codesign --verify --strict "$KIT/Vaultkeeper.app"

mkdir -p target/kit
OUT="target/kit/Vaultkeeper-kit-$VERSION.zip"
rm -f "$OUT"
ditto -c -k --keepParent --norsrc --noextattr --noqtn "$KIT" "$OUT"
echo "built $OUT ($(du -h "$OUT" | cut -f1))"
