# Vaultkeeper on macOS (Apple silicon)

## Build and install

```sh
cd ~/Projects/vaultkeeper
scripts/make-signing-cert.sh   # once; asks for your login password to trust the certificate
scripts/bundle-macos.sh        # -> target/bundle/Vaultkeeper.app
ditto target/bundle/Vaultkeeper.app /Applications/Vaultkeeper.app
open /Applications/Vaultkeeper.app
```

`make-signing-cert.sh` is optional, but recommended. It creates a self-signed "vaultkeeper local"
code-signing certificate, so every rebuild has the same code identity. Without it the bundle is
ad-hoc signed. macOS then asks again "vaultkeeper wants to use your confidential information" for the
keychain item (the refresh token) after each rebuild.

**Signing prompt.** `bundle-macos.sh` shows a keychain prompt ("codesign wants to sign using key
…") on every build. Click **Allow**, not *Always Allow*. The prompt is the protection: Vaultkeeper's
keychain items trust anything signed as "vaultkeeper local", so a key that signs without asking
would let any process sign its own binary as Vaultkeeper and read the refresh token silently.
*Always Allow* re-creates exactly that. While creating the certificate the script also asks once
for your login keychain password (`security set-key-partition-list`); without that step the
codesign prompt rejects even the correct password. If your certificate was made by an older version of the
script (which trusted `codesign` without a prompt), run `scripts/make-signing-cert.sh --recreate`
once; Vaultkeeper then asks one more time for its keychain items after the next build.

The app has no Dock icon. It lives in the menu bar; a Dock icon appears only while the vault
window is open.

Update: quit Vaultkeeper from the tray menu **first**, then rebuild, `ditto` it again and open it.
The background process only accepts a window process with exactly its own code signature, so
a running old version refuses the new one's windows until it is quit.

## First login

1. Open the app; the login window appears.
2. Enter the **server URL** of your Vaultwarden (e.g. `https://vault.example.com`), email and master
   password. Plain `http://` is accepted only for localhost and private-network addresses
   (10.x, 172.16–31.x, 192.168.x, `*.local`).
3. If the account has email 2FA, enter the code from the email. If the server asks for a new-device
   code, enter that.
4. The vault syncs and the Manager window opens.

More accounts: tray menu or sidebar account switcher → *Add account*. *Log out* removes all of that
account's local data: cache, keychain items, Touch ID enrollment, SSH keys in the agent and the
clipboard if it holds a copied secret.

## Daily use

- **Quick Panel:** ⌘⇧Space (Settings → Shortcuts) or the tray icon → *Quick search*. Type, then:
  - Enter copies the password;
  - ⇧Enter copies the username;
  - ⌘Enter copies the TOTP code;
  - ⌘⇧Enter, or the *Auto-type* button on a login row, types the username, Tab and the password
    into the app that was in front when you opened the panel (see *Auto-type* below).
- **Edit conflicts:** if the item changed on another device while you were editing, saving is
  refused with a message; your typed values stay in the form, Cancel loads the latest version.
- **Manager window:** every row has one-click copy buttons for username, password and TOTP (with a
  countdown ring). The sidebar has folders (create, rename, delete), organizations and collections,
  and kinds. The detail pane edits items and attachments.
- **Collections:** the detail pane's *Move to organization…* moves a personal item into an
  organization's collections, as the official clients' *Assign collections* does. This can't be
  undone: the item can't go back to your personal vault or to another organization. On an
  organization item, *Change…* changes which of its collections it is in. Read-only collections
  stay assigned. An item from before per-item keys that has attachments can't be moved here; use
  the official client for those.
- Copied secrets are hidden from clipboard history, and cleared after 30 s (configurable) if the
  clipboard still holds them. The background process does the clearing, so it happens even when
  the windows have closed, and also on lock, log out, account switch and Quit. Time asleep counts.
- **Generator:** in the tray menu, its own global hotkey if you set one (Settings → Shortcuts), and
  the *Generate* button on the password field when editing an item.
- **Settings:** tray menu → *Settings…*, or ⌘, in the Manager.
- **Sync:**
  - live through the server websocket;
  - also on unlock, every 30 min and *Sync now*;
  - the tray's *Sync now* reads *Syncing…* while it runs, and an open Manager shows *Vault synced*
    or why it failed. Under it the tray menu shows *Last synced 12:04* (the date too, if it was
    not today), or the failure until a later sync succeeds.
- **Offline:** when the server can't be reached the app keeps working from the encrypted cache. A
  toast tells you so, and it syncs as soon as the server is back.
- **Lock:** after *Lock after* of inactivity (Settings → Security; *Never* turns the timer off), on
  sleep or screen lock while *Lock on sleep or screen lock* is on (the default), or from the tray.
  A settings file from an older version with *On sleep / screen lock* becomes *Never* plus that
  switch.
- **Broken settings file:** if `settings.json` cannot be read, Vaultkeeper starts with the defaults,
  keeps the old file as `settings.json.broken` and says so once in a window toast.

## Auto-type

Open the Quick Panel with the hotkey (or the tray) while the login form is in front, pick the
login and press ⌘⇧Enter or its *Auto-type* button. The panel closes, the previous app comes back
to the front and Vaultkeeper types `username`, Tab, `password` as key presses (only the password when
the username is empty). Nothing goes through the clipboard. It works for logins with a password.

- Items with *Ask for master password* need it first: open them in the Manager (⌘O) and confirm,
  then *Auto-type* works until the vault locks.
- Typing starts once you let go of ⌘ and ⇧. It stops, and the next window says why, when the app
  does not come back to the front within a second, when another app (or Vaultkeeper) comes to the
  front while typing, when a modifier key is held down, or when the vault locks.
- Opened with ⌘K from the Manager there is no other app to type into; in the Manager ⌘⇧Enter
  opens the item's URI.

**Accessibility permission.** macOS lets an app send key presses to other apps only with the
Accessibility permission. The first *Auto-type* shows the system's request; allow Vaultkeeper in
System Settings → Privacy & Security → Accessibility, then try again. Nothing is typed until it is
allowed. macOS ties the permission to the app's code signature: a build signed with the
"vaultkeeper local" certificate (`scripts/make-signing-cert.sh`) keeps it across rebuilds; an
ad-hoc signed build is a new app to macOS after each rebuild, so remove the old Vaultkeeper entry
from the list and allow it again.

## Touch ID

Settings → Security → Touch ID → *Enrol* (while unlocked).
- The user key is wrapped to a Secure Enclave key that only works with your currently enrolled
  fingerprints.
- Adding or removing a fingerprint disables Touch ID unlock: unlock with the master password and
  enrol again.
- *Require master password on app start* (off by default) forces the password after every launch.
- *Unlock with Touch ID right away* (off by default; available once Touch ID is enrolled) skips
  the lock window: opening the vault, *Unlock* in the tray, the Quick Panel hotkey, *Ask to unlock
  on start* and an SSH request while locked start the Touch ID prompt at once, and on success go
  straight to what you asked for (Manager, Quick Panel, SSH approval). Cancelling or a failure
  opens the usual lock window (the Quick Panel with its password field for the hotkey); after a
  cancel or failure it does not ask again while that window is open. A cancel shows no error;
  other failures show the reason.
  With *Require master password on app start* the first unlock after launch still needs the
  password. Locking (timer, sleep, ⌘⇧L) never starts a prompt by itself.

## SSH agent

Settings → SSH agent → turn on *SSH agent* (the socket path has a copy button there). The keys come from the vault's SSH-key items. The socket is
`~/Library/Application Support/vaultkeeper/ssh-agent.sock`.

Your `~/.ssh/config` currently points every host at the App Store Bitwarden agent:

```
Host *
    IdentityAgent ~/Library/Containers/com.bitwarden.desktop/Data/.bitwarden-ssh-agent.sock
```

To switch to Vaultkeeper, change that line to:

```
    IdentityAgent "~/Library/Application Support/vaultkeeper/ssh-agent.sock"
```

Rollback: restore the old line.

To try it without editing the config:

```sh
SSH_AUTH_SOCK="$HOME/Library/Application Support/vaultkeeper/ssh-agent.sock" ssh-add -l
ssh -o 'IdentityAgent "~/Library/Application Support/vaultkeeper/ssh-agent.sock"' -T git@github.com
```

Each sign request opens an approval window (process and key fingerprint, auto-deny after 30 s).
- *SSH requires Touch ID* asks for a fingerprint after you click Approve.
- *SSH requires approval* can be set to *Remember until lock*, or tick *Remember for this key until lock*
  in the prompt; that key is then not asked again until the vault locks.
- The agent holds keys only while the vault is unlocked. While it is locked, `ssh-add -l` or a
  connection shows the unlock window first and continues after you unlock. While logged out the
  agent lists no keys.

## Browsers

Chrome and Firefox can fill logins from Vaultkeeper and offer to save new or changed passwords. The
browser extension is a thin client: it holds no password, key or copy of the vault. Matching, every
decision and every prompt are in Vaultkeeper's own windows.

1. Settings → Browsers → turn on *Browser integration*, and leave *Install for …* on for the browsers
   you use. This writes the native messaging connection file for each installed browser
   (`~/Library/Application Support/<browser>/NativeMessagingHosts/org.vaultkeeper.browser.json`).
   Integration starts only with the signed app build; otherwise the state line says why.
2. Install the extension (see `browsers/README.md`) and open its popup. The first connection opens a
   *Connect <browser>?* window with a code. Check that it matches the code in the extension popup,
   then click *Connect*. *Deny* is the default; Return does not approve.
3. **Fill:** click the Vaultkeeper icon in a login field, press ⌘⇧L, or use the popup's *Fill this
   page*. A native window lists the logins saved for the site; pick one with the arrows and Return.
   When only one login matches the site it is filled at once, with no window (see the setting below).
   Later fills of the same site in the same browser session need no window until the vault locks, the
   Mac sleeps or the screen locks. *Choose another login…* in the popup always shows the window.
   Picking a login saved for a different site asks for a second confirmation (the default is *Cancel*).
   Logins that require the master password ask for it in the window.
4. **Locked vault:** a fill shows the unlock window first and continues after you unlock.
5. **Save:** after you sign in with a new account or a changed password, a small *Save login?* or
   *Update password?* window appears in the top-right corner without taking focus from the browser,
   so answer it with the mouse. It also times out after 30 s (*Not now*). *Never for this site*
   stops the offers for that site. Nothing is offered in private windows, on unencrypted sites other
   than local ones, or when the stored password is already the same.
6. **Settings:** *Require Touch ID to fill* (asked for every fill, including remembered ones and single matches), *Fill at once when only one login matches* (on by default: with exactly one saved login for an encrypted page, no picker is shown; sites with several matches, `http` pages and re-prompt items still show it),
   *Offer to save logins*, *Copy TOTP code after filling*
   (the code goes to the clipboard and is cleared like other copies) and *Match sites by* (*Domain*
   or *Exact host*, for saved addresses without their own rule; a saved address's own match
   rule from the Bitwarden web vault always wins). *Paired browsers* lists each connection with its
   fingerprint and a *Remove* button; removing it closes that browser's live connection.

The activity log is `~/Library/Logs/vaultkeeper/browser.log`: time, browser, host and item id of
every fill, never a secret.

Known limits:

- Malware running as your macOS user can drive a real browser with a copied profile, so pairing and
  the browser signature check are barriers, not guarantees. Nothing is released without a click in a
  Vaultkeeper window, and remembered approvals belong to one live connection.
- A filled password can be read by scripts of the page it was filled into (for example after XSS).
- JavaScript strings cannot be wiped; the extension keeps a credential only for one message hand-off.
- The parent-process check can be bypassed by starting the host and then replacing its parent.
- Equivalent-domain lists and filling on page load are not supported; autofill needs a click or the
  shortcut on purpose.

To remove a browser, turn off *Install for …* (the connection file is deleted), remove the pairing,
and remove the extension in the browser.

## Start at login

Settings → Security → *Start at login*. This installs `~/Library/LaunchAgents/vaultkeeper.plist`, which
starts `vaultkeeper --tray`, so only the menu bar icon shows. *Ask to unlock on start* opens the unlock
window at launch.
- Enable it from the copy in `/Applications`, because the agent stores the path of the executable
  that enabled it.
- To remove it: turn the setting off, or `rm ~/Library/LaunchAgents/vaultkeeper.plist`.
- After a crash macOS starts Vaultkeeper again (`KeepAlive` on a failed exit); *Quit* from the tray
  stays quit. An agent written by an older version is updated on its next start at login.

## Themes

Settings → Appearance → Theme: *System* (follows macOS live), *Light*, or *Dark*. Text size is there too.

Settings → Shortcuts → *Quick Panel hotkey* / *Generator hotkey* are shortcut recorders: click one,
it shows *Press a shortcut…*, then press the combination. It needs ⌘, ⌥ or ⌃ (⇧ can be added, but
not on its own) plus a letter, digit, Space, F1–F12, Return, Tab, an arrow or one of
`` ` \ [ ] , - . ' ; / = ``. It is saved at once and works system-wide straight away. Esc or
clicking elsewhere cancels; Delete or Backspace removes the Generator hotkey (the Quick Panel always
keeps one). The two can't be the same shortcut. Keys are recorded by their position on the
keyboard, as macOS matches global shortcuts, so ⌥ letters and non-Latin layouts record the key
itself. While a recorder waits, Vaultkeeper's own global hotkeys are off, so pressing the current
Quick Panel hotkey records it instead of opening the panel. They come back when recording ends,
when Settings closes, if the window process goes away, and in any case after 30 s. A combination
another app or macOS holds as a global shortcut still never reaches the recorder.

## Files

| Path | Content |
|---|---|
| `~/Library/Application Support/vaultkeeper/` | settings, encrypted vault cache per account, sockets (mode 0600) |
| `…/vaultkeeper/browsers.json`, `browser.sock` | browser pairings (public keys only) and the browser socket |
| login keychain, items prefixed `vaultkeeper` | refresh tokens |
| `~/Library/LaunchAgents/vaultkeeper.plist` | only with *Start at login* |
| `~/Library/Logs/vaultkeeper/daemon.log`, `ui.log`, `browser.log` | logs of the two processes, at most 1 MiB each plus one older `.1` file; not meant to hold secrets |

To uninstall:
1. Log out of each account in the app, then quit it.
2. `rm -rf /Applications/Vaultkeeper.app "$HOME/Library/Application Support/vaultkeeper" ~/Library/LaunchAgents/vaultkeeper.plist ~/Library/Logs/vaultkeeper`.

## Command line

```
vaultkeeper            start (or ask the running instance) and open the vault window
vaultkeeper --tray     menu bar only
vaultkeeper --quick    open the Quick Panel
vaultkeeper --mock     run on a built-in demo vault (master password: mock), touches no real data
```

## Development

```sh
scripts/check.sh                                     # fmt + clippy (also the pre-commit hook)
SLINT_BACKEND=winit-software cargo test --workspace  # unit + integration tests
scripts/e2e.sh                                       # e2e against docker Vaultwarden + Mailpit
```
