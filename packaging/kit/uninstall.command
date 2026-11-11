#!/usr/bin/env bash
# Removes the app and the extension files. Saved logins stay on your Vaultwarden server.
set -euo pipefail

pkill -x vaultkeeper 2>/dev/null || true
sleep 1
rm -rf /Applications/Vaultkeeper.app
rm -rf "$HOME/Library/Application Support/Vaultkeeper"
rm -f "$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.vaultkeeper.browser.json"
echo "Removed. Also remove the extension in chrome://extensions."
