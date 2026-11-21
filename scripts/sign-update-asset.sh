#!/usr/bin/env bash
# Writes <asset>.minisig in the updater's format (app/src/daemon/update/signature.rs): the
# minisign container with a different message, so stock minisign can neither produce nor verify
# it. The Ed25519 signature is over "Ed" || key id || SHA-512(asset), the global one over
# "Ed" || key id || signature || trusted comment ("vaultkeeper <version> <asset name>").
#   UPDATE_SIGNING_KEY=<Ed25519 PKCS#8 PEM> scripts/sign-update-asset.sh <asset path> <version>
set -euo pipefail

asset_path=$1
version=$2
asset=$(basename "$asset_path")
: "${UPDATE_SIGNING_KEY:?UPDATE_SIGNING_KEY must hold the Ed25519 private key}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
printf '%s\n' "$UPDATE_SIGNING_KEY" > "$work/key.pem"
openssl pkey -in "$work/key.pem" -pubout -out "$work/pub.pem"
openssl pkey -in "$work/key.pem" -pubout -outform DER | tail -c 32 > "$work/pub"
{ printf Ed; cat "$work/pub"; } | openssl dgst -sha512 -binary | head -c 8 > "$work/keyid"
{ printf Ed; cat "$work/keyid"; openssl dgst -sha512 -binary < "$asset_path"; } > "$work/msg"
openssl pkeyutl -sign -inkey "$work/key.pem" -rawin -in "$work/msg" -out "$work/sig"
{ printf Ed; cat "$work/keyid" "$work/sig"; } > "$work/blob"
{ cat "$work/blob"; printf 'vaultkeeper %s %s' "$version" "$asset"; } > "$work/gmsg"
openssl pkeyutl -sign -inkey "$work/key.pem" -rawin -in "$work/gmsg" -out "$work/gsig"
openssl pkeyutl -verify -pubin -inkey "$work/pub.pem" -rawin -in "$work/msg" -sigfile "$work/sig"
openssl pkeyutl -verify -pubin -inkey "$work/pub.pem" -rawin -in "$work/gmsg" -sigfile "$work/gsig"
{
    echo "untrusted comment: vaultkeeper release signature"
    base64 < "$work/blob" | tr -d '\n'; echo
    echo "trusted comment: vaultkeeper $version $asset"
    base64 < "$work/gsig" | tr -d '\n'; echo
} > "$asset_path.minisig"
