#!/bin/sh
# Lays out and packs the Linux release tarball for one target triple:
#   vaultkeeper-v<version>-<triple>/{bin/vaultkeeper, share/vaultkeeper/{install-kind, icons/},
#   LICENSE} → out/vaultkeeper-v<version>-<triple>.tar.gz
# Fails when the binary links a library outside packaging/linux/allowed-libs.txt, so the
# formula's runtime package list stays true.
#   scripts/bundle-linux.sh <triple> [install kind, default homebrew]
set -e

cd "$(dirname "$0")/.."

triple=$1
kind=${2:-homebrew}
if [ -z "$triple" ]; then
    echo "usage: $0 <target triple> [install kind]" >&2
    exit 1
fi
version=$(scripts/version.sh)
binary="target/$triple/release/vaultkeeper"
name="vaultkeeper-v$version-$triple"
stage="out/$name"

needed=$(readelf -d "$binary" | sed -n 's/.*Shared library: \[\(.*\)\]/\1/p')
echo "$binary links:"
echo "$needed" | sed 's/^/  /'
unexpected=$(echo "$needed" | grep -vxF -f packaging/linux/allowed-libs.txt || true)
if [ -n "$unexpected" ]; then
    echo "::error::$binary links libraries outside packaging/linux/allowed-libs.txt: $unexpected" >&2
    exit 1
fi

rm -rf "$stage"
mkdir -p "$stage/bin" "$stage/share/vaultkeeper/icons"
install -m 0755 "$binary" "$stage/bin/vaultkeeper"
printf '%s\n' "$kind" > "$stage/share/vaultkeeper/install-kind"
install -m 0644 packaging/macos/icon.svg "$stage/share/vaultkeeper/icons/io.github.avbel.Vaultkeeper.svg"
install -m 0644 LICENSE "$stage/LICENSE"
tar -C out -czf "out/$name.tar.gz" "$name"
echo "out/$name.tar.gz"
