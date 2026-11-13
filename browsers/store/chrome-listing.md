# Chrome Web Store listing

The upload API does not change the listing, so these answers are pasted into the developer dashboard by hand.
Keep the description in sync with the AMO text in `amo-metadata.json`, which the release workflow sends on every Firefox
submission.

## Store listing tab

- **Description:** below.
- **Category:** Tools. **Language:** English.
- **Store icon:** `dist/chrome/icons/icon-128.png`.
- **Small promo tile (440×280):** `store/promo-small-440x280.png`.
- **Screenshots (1280×800 or 640×400, at least one):** take them by hand in Chrome on a real login page.
- **Official URL:** none. **Homepage URL:** https://github.com/avbel/vaultkeeper
- **Support URL:** https://github.com/avbel/vaultkeeper/issues

### Description

Vaultkeeper fills logins and passkeys on web pages from the Vaultkeeper desktop app, a lightweight native client for
self-hosted Vaultwarden servers, and offers to save new passwords.

The extension is a thin client. It never holds your vault, your master password or a list of logins: each request goes
to the app over native messaging, and the app shows its own window to choose a login.

Requires the Vaultkeeper app on macOS 13 or newer (Apple silicon): https://github.com/avbel/vaultkeeper/releases

Windows and Linux are coming soon.

Vaultkeeper is an independent project, not affiliated with Bitwarden Inc. or the Vaultwarden project.

## Privacy tab

### Single purpose

Fill and save website logins and passkeys from the Vaultkeeper password manager app installed on the same computer.

### Permission justifications

- **nativeMessaging:** The extension has no vault of its own. Every fill, save and passkey request goes to the
  Vaultkeeper desktop app through native messaging, and the app answers with only the one login the user picked.
- **contextMenus:** Adds "Fill with Vaultkeeper" and "Choose another login…" to the right-click menu of editable fields.
- **scripting:** When a tab was already open before the extension was installed or updated, it has no content script.
  The extension then injects its own bundled content script into that tab, only after the user asks to fill it. No
  remote code is injected.
- **Host permissions (https://\*/\*, http://\*/\*):** Login forms and passkey requests can appear on any website. The
  content script detects login fields to show the fill icon, fills the login the user chose, offers to save a submitted
  password, and passes the site's WebAuthn (passkey) requests to the app. It reads nothing else from the page.

### Remote code

No, I am not using remote code. All JavaScript is in the package.

### Data usage

What user data the item collects or uses:

- [x] **Authentication information:** usernames and passwords filled or submitted on login forms, and passkey
      requests. They are passed only to the Vaultkeeper app on the same computer.
- [x] **Website content:** the login form fields on the page, to detect and fill them.
- [ ] Every other category.

Certify all three statements:

- I do not sell or transfer user data to third parties, outside of the approved use cases.
- I do not use or transfer user data for purposes that are unrelated to my item's single purpose.
- I do not use or transfer user data to determine creditworthiness or for lending purposes.

**Privacy policy URL:** https://github.com/avbel/vaultkeeper/blob/main/PRIVACY.md

## Distribution tab

Public, all regions. Paid features: none.

## Test instructions (for reviewers)

The extension works only with the Vaultkeeper app (macOS 13+, Apple silicon) from
https://github.com/avbel/vaultkeeper/releases, signed in to a Vaultwarden server. The app's `--mock` demo vault
runs without the background service the extension talks to, so it cannot be used here; put a test server URL, email
and master password in the dashboard's test credentials.

1. Install the app (drag it to Applications, then System Settings → Privacy & Security → Open Anyway) and sign in.
2. Settings → Browsers → turn on _Browser integration_, with _Install for Chrome_ on.
3. Install the extension, open a login page and click the Vaultkeeper icon in the field or the toolbar popup. The app
   asks once to pair this browser.
