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

The app has no Dock icon. It lives in the menu bar; a Dock icon appears only while the vault
window is open.

Update: quit bw-lite from the tray menu, rebuild, `ditto` it again and open it.

## First login

1. Open the app; the login window appears.
2. Enter the **server URL** of your Vaultwarden (e.g. `https://vault.example.com`), email and master
   password. Use `http://` only for `localhost`.
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
  - ⌘Enter copies the TOTP code.
- **Manager window:** every row has one-click copy buttons for username, password and TOTP (with a
  countdown ring). The sidebar has folders (create, rename, delete), organizations and collections,
  and kinds. The detail pane edits items and attachments.
- Copied secrets are hidden from clipboard history, and cleared after 30 s (configurable) if the
  clipboard still holds them.
- **Generator:** in the tray menu, and the *Generate* button on the password field when editing an item.
- **Sync:**
  - live through the server websocket;
  - also on unlock, every 30 min and *Sync now*.
- **Offline:** when the server can't be reached the app keeps working from the encrypted cache. A
  toast tells you so, and it syncs as soon as the server is back.
- **Lock:** after *Lock after* (Settings → Security; includes *On sleep / screen lock*), or from the tray.

## Touch ID

Settings → Security → Touch ID → *Enrol* (while unlocked).
- The user key is wrapped to a Secure Enclave key that only works with your currently enrolled
  fingerprints.
- Adding or removing a fingerprint disables Touch ID unlock: unlock with the master password and
  enrol again.
- *Require master password on app start* (off by default) forces the password after every launch.

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
ssh -o IdentityAgent="~/Library/Application Support/bw-lite/ssh-agent.sock" -T git@github.com
```

Each sign request opens an approval window (process and key fingerprint, auto-deny after 30 s).
- *SSH requires Touch ID* asks for a fingerprint instead.
- *SSH requires approval* can be set to *Remember until lock*, or tick *Remember for this key until lock*
  in the prompt; that key is then not asked again until the vault locks.
- While the vault is locked a request shows the unlock window first.

## Start at login

Settings → Security → *Start at login*. This installs `~/Library/LaunchAgents/bw-lite.plist`, which
starts `bw-lite --tray`, so only the menu bar icon shows. *Ask to unlock on start* opens the unlock
window at launch.
- Enable it from the copy in `/Applications`, because the agent stores the path of the executable
  that enabled it.
- To remove it: turn the setting off, or `rm ~/Library/LaunchAgents/bw-lite.plist`.

## Themes

Settings → Appearance → Theme: *System* (follows macOS live), *Light*, or *Dark*. Text size is there too.

## Files

| Path | Content |
|---|---|
| `~/Library/Application Support/bw-lite/` | settings, encrypted vault cache per account, sockets (mode 0600) |
| login keychain, items prefixed `bw-lite` | refresh tokens |
| `~/Library/LaunchAgents/bw-lite.plist` | only with *Start at login* |

To uninstall:
1. Log out of each account in the app, then quit it.
2. `rm -rf /Applications/bw-lite.app "~/Library/Application Support/bw-lite" ~/Library/LaunchAgents/bw-lite.plist`.

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
