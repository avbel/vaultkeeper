#!/usr/bin/env bash
# Creates a self-signed code-signing certificate "vaultkeeper local" in the login keychain, once.
# No Apple Developer account is involved; the certificate only gives local builds a stable code
# identity. macOS asks for your login password when the certificate is marked trusted.
#
#   scripts/make-signing-cert.sh              # create it if missing
#   scripts/make-signing-cert.sh --recreate   # replace one made by an older version of this script
#
# The private key trusts no application (`-T ""`; without any -T the importing /usr/bin/security
# would stay trusted for signing): every use of it, i.e. each `codesign` run in bundle-macos.sh,
# shows a keychain prompt. Older versions trusted
# /usr/bin/codesign, so any process could sign any binary as "vaultkeeper local" without a prompt,
# and that binary would then read vaultkeeper's keychain items (the refresh token) without a prompt
# too, because they trust this identity. Answer the prompt with "Allow", never "Always Allow":
# that would put codesign back on the key's access list.
set -euo pipefail

NAME="${VAULTKEEPER_SIGN_IDENTITY:-vaultkeeper local}"
KEYCHAIN="$HOME/Library/Keychains/login.keychain-db"

if [ "${1:-}" = "--recreate" ]; then
  while security find-certificate -c "$NAME" "$KEYCHAIN" >/dev/null 2>&1; do
    security delete-identity -c "$NAME" "$KEYCHAIN" >/dev/null 2>&1 \
      || security delete-certificate -c "$NAME" "$KEYCHAIN"
  done
  echo "removed \"$NAME\"; vaultkeeper asks once for its keychain items after the next build"
elif security find-identity -v -p codesigning | grep -q "\"$NAME\""; then
  echo "\"$NAME\" already exists (use --recreate if an older version of this script made it)"
  exit 0
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cat > "$WORK/cert.cnf" <<CNF
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = $NAME
[ext]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, codeSigning
CNF
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -config "$WORK/cert.cnf" \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" 2>/dev/null
PASS=$(openssl rand -hex 16)
openssl pkcs12 -export -legacy -inkey "$WORK/key.pem" -in "$WORK/cert.pem" \
  -name "$NAME" -passout "pass:$PASS" -out "$WORK/id.p12" 2>/dev/null \
  || openssl pkcs12 -export -inkey "$WORK/key.pem" -in "$WORK/cert.pem" \
       -name "$NAME" -passout "pass:$PASS" -out "$WORK/id.p12"
security import "$WORK/id.p12" -k "$KEYCHAIN" -P "$PASS" -T ""
# Without Apple tools in the key's partition list, codesign's prompt rejects even the correct
# login password. This asks for the login keychain password itself (never pass it with -k on the
# command line). It does not trust any application: each codesign run still prompts.
echo "Enter your login keychain password to let codesign ask for the key:"
security set-key-partition-list -S apple-tool:,apple: -s -l "$NAME" "$KEYCHAIN" >/dev/null
security add-trusted-cert -p codeSign -k "$KEYCHAIN" "$WORK/cert.pem"
security find-identity -v -p codesigning | grep "\"$NAME\""
