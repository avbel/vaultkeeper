# bw-lite on macOS (Apple silicon)

## Build and install

```sh
cd ~/Projects/bw-lite-desktop
scripts/make-signing-cert.sh   # once; asks for your login password to trust the certificate
scripts/bundle-macos.sh        # -> target/bundle/bw-lite.app
ditto target/bundle/bw-lite.app /Applications/bw-lite.app
open /Applications/bw-lite.app
```

`make-signing-cert.sh` is optional, but recommended. It creates a self-signed "bw-lite local"
code-signing certificate, so every rebuild has the same code identity. Without it the bundle is
ad-hoc signed. macOS then asks again "bw-lite wants to use your confidential information" for the
keychain item (the refresh token) after each rebuild.

**Signing prompt.** `bundle-macos.sh` shows a keychain prompt ("codesign wants to sign using key
…") on every build. Click **Allow**, not *Always Allow*. The prompt is the protection: bw-lite's
keychain items trust anything signed as "bw-lite local", so a key that signs without asking
would let any process sign its own binary as bw-lite and read the refresh token silently.
*Always Allow* re-creates exactly that. While creating the certificate the script also asks once
for your login keychain password (`security set-key-partition-list`); without that step the
codesign prompt rejects even the correct password. If your certificate was made by an older version of the
script (which trusted `codesign` without a prompt), run `scripts/make-signing-cert.sh --recreate`
once; bw-lite then asks one more time for its keychain items after the next build.

The app has no Dock icon. It lives in the menu bar; a Dock icon appears only while the vault
window is open.

Update: quit bw-lite from the tray menu **first**, then rebuild, `ditto` it again and open it.
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
- Copied secrets are hidden from clipboard history, and cleared after 30 s (configurable) if the
  clipboard still holds them. The background process does the clearing, so it happens even when
  the windows have closed, and also on lock, log out, account switch and Quit. Time asleep counts.
- **Generator:** in the tray menu, its own global hotkey if you set one (Settings → Shortcuts), and
  the *Generate* button on the password field when editing an item.
- **Settings:** tray menu → *Settings…*, or ⌘, in the Manager.
- **Sync:**
  - live through the server websocket;
  - also on unlock, every 30 min and *Sync now*.
- **Offline:** when the server can't be reached the app keeps working from the encrypted cache. A
  toast tells you so, and it syncs as soon as the server is back.
- **Lock:** after *Lock after* of inactivity (Settings → Security; *Never* turns the timer off), on
  sleep or screen lock while *Lock on sleep or screen lock* is on (the default), or from the tray.
  A settings file from an older version with *On sleep / screen lock* becomes *Never* plus that
  switch.
- **Broken settings file:** if `settings.json` cannot be read, bw-lite starts with the defaults,
  keeps the old file as `settings.json.broken` and says so once in a window toast.

## Auto-type

Open the Quick Panel with the hotkey (or the tray) while the login form is in front, pick the
login and press ⌘⇧Enter or its *Auto-type* button. The panel closes, the previous app comes back
to the front and bw-lite types `username`, Tab, `password` as key presses (only the password when
the username is empty). Nothing goes through the clipboard. It works for logins with a password.

- Items with *Ask for master password* need it first: open them in the Manager (⌘O) and confirm,
  then *Auto-type* works until the vault locks.
- Typing starts once you let go of ⌘ and ⇧. It stops, and the next window says why, when the app
  does not come back to the front within a second, when another app (or bw-lite) comes to the
  front while typing, when a modifier key is held down, or when the vault locks.
- Opened with ⌘K from the Manager there is no other app to type into; in the Manager ⌘⇧Enter
  opens the item's URI.

**Accessibility permission.** macOS lets an app send key presses to other apps only with the
Accessibility permission. The first *Auto-type* shows the system's request; allow bw-lite in
System Settings → Privacy & Security → Accessibility, then try again. Nothing is typed until it is
allowed. macOS ties the permission to the app's code signature: a build signed with the
"bw-lite local" certificate (`scripts/make-signing-cert.sh`) keeps it across rebuilds; an
ad-hoc signed build is a new app to macOS after each rebuild, so remove the old bw-lite entry
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
`~/Library/Application Support/bw-lite/ssh-agent.sock`.

Your `~/.ssh/config` currently points every host at the App Store Bitwarden agent:

```
Host *
    IdentityAgent /Users/avbel/Library/Containers/com.bitwarden.desktop/Data/.bitwarden-ssh-agent.sock
```

To switch to bw-lite, change that line to:

```
    IdentityAgent "~/Library/Application Support/bw-lite/ssh-agent.sock"
```

Rollback: restore the old line.

To try it without editing the config:

```sh
SSH_AUTH_SOCK="$HOME/Library/Application Support/bw-lite/ssh-agent.sock" ssh-add -l
ssh -o 'IdentityAgent "~/Library/Application Support/bw-lite/ssh-agent.sock"' -T git@github.com
```

Each sign request opens an approval window (process and key fingerprint, auto-deny after 30 s).
- *SSH requires Touch ID* asks for a fingerprint after you click Approve.
- *SSH requires approval* can be set to *Remember until lock*, or tick *Remember for this key until lock*
  in the prompt; that key is then not asked again until the vault locks.
- The agent holds keys only while the vault is unlocked. While it is locked, `ssh-add -l` or a
  connection shows the unlock window first and continues after you unlock. While logged out the
  agent lists no keys.

## Start at login

Settings → Security → *Start at login*. This installs `~/Library/LaunchAgents/bw-lite.plist`, which
starts `bw-lite --tray`, so only the menu bar icon shows. *Ask to unlock on start* opens the unlock
window at launch.
- Enable it from the copy in `/Applications`, because the agent stores the path of the executable
  that enabled it.
- To remove it: turn the setting off, or `rm ~/Library/LaunchAgents/bw-lite.plist`.
- After a crash macOS starts bw-lite again (`KeepAlive` on a failed exit); *Quit* from the tray
  stays quit. An agent written by an older version is updated on its next start at login.

## Themes

Settings → Appearance → Theme: *System* (follows macOS live), *Light*, or *Dark*. Text size is there too.

Settings → Shortcuts → *Show keyboard shortcuts* (on by default). Off hides the shortcut hints:
button suffixes such as *Lock ⌘⇧L*, key caps in fields (*⌘F*, *Esc*), *Settings ⌘,* on the lock
window and *⌘⇧↩* next to the Quick Panel's Auto-type button. The tray menu never shows
shortcuts. Every open window follows at once. The
shortcuts keep working, and the key legends stay: the Quick Panel footer (Enter, ⇧Enter, ⌘Enter…)
and the Manager's empty detail pane.

Settings → Shortcuts → *Quick Panel hotkey* / *Generator hotkey* are shortcut recorders: click one,
it shows *Press a shortcut…*, then press the combination. It needs ⌘, ⌥ or ⌃ (⇧ can be added, but
not on its own) plus a letter, digit, Space, F1–F12, Return, Tab, an arrow or one of
`` ` \ [ ] , - . ' ; / = ``. It is saved at once and works system-wide straight away. Esc or
clicking elsewhere cancels; Delete or Backspace removes the Generator hotkey (the Quick Panel always
keeps one). The two can't be the same shortcut. Keys are recorded by their position on the
keyboard, as macOS matches global shortcuts, so ⌥ letters and non-Latin layouts record the key
itself. While a recorder waits, bw-lite's own global hotkeys are off, so pressing the current
Quick Panel hotkey records it instead of opening the panel. They come back when recording ends,
when Settings closes, if the window process goes away, and in any case after 30 s. A combination
another app or macOS holds as a global shortcut still never reaches the recorder.

## Files

| Path | Content |
|---|---|
| `~/Library/Application Support/bw-lite/` | settings, encrypted vault cache per account, sockets (mode 0600) |
| login keychain, items prefixed `bw-lite` | refresh tokens |
| `~/Library/LaunchAgents/bw-lite.plist` | only with *Start at login* |
| `~/Library/Logs/bw-lite/daemon.log`, `ui.log` | logs of the two processes, at most 1 MiB each plus one older `.1` file; not meant to hold secrets |

To uninstall:
1. Log out of each account in the app, then quit it.
2. `rm -rf /Applications/bw-lite.app "$HOME/Library/Application Support/bw-lite" ~/Library/LaunchAgents/bw-lite.plist ~/Library/Logs/bw-lite`.

## Command line

```
bw-lite            start (or ask the running instance) and open the vault window
bw-lite --tray     menu bar only
bw-lite --quick    open the Quick Panel
bw-lite --mock     run on a built-in demo vault (master password: mock), touches no real data
```

## Development

```sh
scripts/check.sh                                     # fmt + clippy (also the pre-commit hook)
SLINT_BACKEND=winit-software cargo test --workspace  # unit + integration tests
scripts/e2e.sh                                       # e2e against docker Vaultwarden + Mailpit
```
