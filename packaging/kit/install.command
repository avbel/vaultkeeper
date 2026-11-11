#!/usr/bin/env bash
# Installs Vaultkeeper and the Chrome extension files from this folder. Safe to run again to update.
set -euo pipefail

cd "$(dirname "$0")"
APP_SRC="Vaultkeeper.app"
EXT_SRC="chrome-extension"
APP_DST="/Applications/Vaultkeeper.app"
EXT_DST="$HOME/Library/Application Support/Vaultkeeper/chrome-extension"

if [ ! -d "$APP_SRC" ] || [ ! -d "$EXT_SRC" ]; then
  echo "Run this from the unzipped kit folder: Vaultkeeper.app and chrome-extension must sit next to it." >&2
  exit 1
fi
if [ "$(uname -m)" != "arm64" ]; then
  echo "This build runs on Apple silicon Macs only (M1 or newer)." >&2
  exit 1
fi

echo "1/4 Closing Vaultkeeper if it is running"
pkill -x vaultkeeper 2>/dev/null || true
sleep 1

echo "2/4 Installing the app into /Applications"
rm -rf "$APP_DST"
ditto "$APP_SRC" "$APP_DST"
# A downloaded copy carries a quarantine flag that makes macOS refuse the app (it is not notarized).
xattr -dr com.apple.quarantine "$APP_DST" 2>/dev/null || true

echo "3/4 Copying the Chrome extension"
rm -rf "$EXT_DST"
mkdir -p "$(dirname "$EXT_DST")"
ditto "$EXT_SRC" "$EXT_DST"

echo "4/4 Starting Vaultkeeper"
open "$APP_DST"

cat <<MSG

Done. Vaultkeeper is in /Applications and its icon is in the menu bar.
Next: follow step 3 of INSTALL.md to add the extension to Chrome.
The extension folder is:
  $EXT_DST
MSG
open -R "$EXT_DST" 2>/dev/null || true
