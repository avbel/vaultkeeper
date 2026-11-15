#!/usr/bin/env bash
# Builds packaging/windows/vaultkeeper.ico (16–256 px) from the app icon SVG. The .ico is
# committed so a Windows build never needs rsvg-convert or ImageMagick; run this only when the
# icon changes.
set -euo pipefail

cd "$(dirname "$0")/.."

SVG=packaging/macos/icon.svg
OUT=packaging/windows/vaultkeeper.ico

if ! command -v rsvg-convert >/dev/null 2>&1; then
  echo "rsvg-convert not found (brew install librsvg)" >&2
  exit 1
fi
if command -v magick >/dev/null 2>&1; then
  MAGICK=magick
elif command -v convert >/dev/null 2>&1; then
  MAGICK=convert
else
  echo "ImageMagick not found (brew install imagemagick)" >&2
  exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

SIZES="16 20 24 32 48 64 256"
for size in $SIZES; do
  rsvg-convert -w "$size" -h "$size" "$SVG" -o "$TMP/icon-$size.png"
done

set --
for size in $SIZES; do
  set -- "$@" "$TMP/icon-$size.png"
done
"$MAGICK" "$@" "$OUT"
echo "wrote $OUT"
