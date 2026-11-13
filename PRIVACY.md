# Privacy policy

Applies to the Vaultkeeper desktop app and the Vaultkeeper browser extension for Chrome and Firefox. Last updated
2026-11-13.

## Summary

Vaultkeeper has no servers, no accounts of its own, no analytics and no advertising. The developer receives no data
from you.

## Browser extension

The extension is a thin client for the Vaultkeeper app on the same computer. It talks only to that app, through the
browser's native messaging, and never sends anything over the network.

What it handles, and only to fill or save logins:

- **The address of the page** (origin and path) where you ask to fill, save, or use a passkey, so the app can find the
  matching logins.
- **The username and password you submit** on a login form, passed to the app, which asks you whether to save them. Nothing
  is stored unless you confirm in the app.
- **Passkey requests** a site makes, passed to the app so you can sign in with or save a passkey from your vault.
- **The login you choose in the app**, which the extension types into the page and then discards.

What it stores: a key pair that pairs this browser profile with the app, kept in the extension's own storage. It never
stores your vault, your master password or a list of logins.

It does not read or keep your browsing history, does not send page content anywhere, and does not run code fetched from
the internet.

## Desktop app

Apart from update checks (below), the app connects only to the Vaultwarden (Bitwarden-compatible) server you sign in
to, and, if you enable website icons, fetches them through that server. Your vault is cached on disk encrypted; the refresh token is kept in the macOS
keychain. Data sent to your server is governed by whoever runs that server.

With *Update automatically* on (the default), the app asks GitHub's API once a day for the latest Vaultkeeper release
and downloads it from GitHub when it is newer. Like any web request, this shows GitHub your IP address, and the request
names the installed Vaultkeeper version; nothing else is sent. With the setting off, the app contacts GitHub only when
you click *Check for Updates…*.

## Contact

Questions: [open an issue](https://github.com/avbel/vaultkeeper/issues).
