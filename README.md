# Vaultkeeper

Vaultkeeper is a lightweight native macOS (Apple silicon) desktop client for self-hosted
[Vaultwarden](https://github.com/dani-garcia/vaultwarden) servers, which speak the Bitwarden API. It is written in Rust with a
[Slint](https://slint.dev) UI, lives in the menu bar, and opens a window only when you need one.

Vaultkeeper is an independent project. It is **not affiliated with, endorsed by or supported by Bitwarden Inc. or the
Vaultwarden project**. It is tested against Vaultwarden 1.37.5 (see `tests/e2e/compose.yaml`).

## Why not Bitwarden Desktop?

- **No Electron.** Electron apps ship a full Chromium and Node.js runtime. Vaultkeeper is a single Rust binary.
- **No JavaScript.** The UI is written in Slint and drawn by its software renderer, with no web view.
- **Small memory footprint.** A background daemon owns the tray icon, the vault, sync and the SSH agent. Windows run in a
  separate UI process of the same binary, which exits about 120 s after the last window closes. When no window is open, memory
  stays at the tray-only level.
- **Fast, native Rust.** Crypto, networking and the vault logic are plain Rust, and the Quick Panel stays warm for 120 s
  after use so repeated opens are instant.

Measured on the Slint spike (Slint 1.18.1, release build, software renderer, physical footprint), not on the finished app:

| State | Memory |
|---|---|
| Tray only (daemon) | ~14 MB |
| Window shown | ~47 MB |

The two-process design exists because the window's memory is not fully returned after it closes (about 42 MB 10 s after the
spike's window was dropped). See the "Step 0 result" section of
[docs/solutions/vaultkeeper-architecture.md](docs/solutions/vaultkeeper-architecture.md).

## Features

- Quick Panel with a global hotkey and fuzzy search: copy password, username or TOTP code from the keyboard
- Manager window: folders, organizations and collections, moving items into an organization or between collections,
  attachments, trash
- TOTP codes with a countdown
- Password and passphrase generator, from the tray or its own hotkey
- Auto-type of username and password into the previous app (key presses, no clipboard)
- SSH agent for the vault's SSH keys, with approval prompts and optional Touch ID
- Read-only [CLI access](#cli-access) for individual logins you choose to share
- Chrome and Firefox extension that fills and saves logins through native Vaultkeeper windows (see `docs/USAGE.md`)
- Touch ID unlock (key wrapped to the Secure Enclave)
- Multiple accounts
- Offline mode from an encrypted local cache
- Live sync over the server websocket
- Clipboard auto-clear, and copied secrets are hidden from clipboard history
- Start at login (tray only)

## Requirements

- macOS 13 or newer on Apple silicon
- Rust toolchain: the version is pinned in `rust-toolchain.toml` and installed automatically by `rustup`
- Xcode Command Line Tools (`xcode-select --install`), needed to build the Swift shim in `crates/platform/swift`
- A Vaultwarden server (or try the demo vault below)

## Build and install

```sh
git clone https://github.com/avbel/vaultkeeper.git
cd vaultkeeper
scripts/make-signing-cert.sh   # once; creates a local code-signing certificate
scripts/bundle-macos.sh        # -> target/bundle/Vaultkeeper.app
ditto target/bundle/Vaultkeeper.app /Applications/Vaultkeeper.app
open /Applications/Vaultkeeper.app
```

The certificate step is optional but recommended: a stable code identity keeps keychain access and the Accessibility
permission across rebuilds. Details, including the signing prompt, are in [docs/USAGE.md](docs/USAGE.md).

To look around without a server, run the built-in demo vault. It touches no real data:

```sh
/Applications/Vaultkeeper.app/Contents/MacOS/vaultkeeper --mock   # master password: mock
```

## Usage

Log in with your server URL, email and master password, then use the tray icon or the Quick Panel hotkey. The user guide
[docs/USAGE.md](docs/USAGE.md) covers first login, the Quick Panel keys, auto-type and the Accessibility permission, Touch ID,
the SSH agent setup, start at login, settings, files and uninstalling.

```
vaultkeeper            start (or ask the running instance) and open the vault window
vaultkeeper --tray     menu bar only
vaultkeeper --quick    open the Quick Panel
vaultkeeper --mock     demo vault
```

### CLI access

1. Keep Vaultkeeper running and turn on **Enable CLI access** in Settings.
2. Edit each login you want to share, check **Allow CLI access**, and save. Both controls are off by default.
3. Copy the terminal setup command from Settings. For the standard installation, run this in sh, Bash, or Zsh, or add it to
   your shell startup file. If an AI agent uses a separate shell, add the same directory to that shell's `PATH`.

   ```sh
   export PATH="/Applications/Vaultkeeper.app/Contents/MacOS:$PATH"
   ```

| Command | Output |
|---|---|
| `vaultkeeper list` | JSON array with a `key` and `title` for each eligible login |
| `vaultkeeper get_fields <key>` | JSON array describing non-empty fields with `field`, `label`, and `private` |
| `vaultkeeper get <key> <field> [--allow-private]` | The selected field as plain text, without an added newline |
| `vaultkeeper --help` | Usage and guidance for AI agents |
| `vaultkeeper --version` | Installed version |

The CLI uses an encrypted connection to the desktop app. Programs running as you can read opted-in logins from the active
account while it is unlocked. Logins that require a master password re-prompt are excluded. If the vault is locked,
Vaultkeeper prompts you to unlock it in the app. Unlock it, then retry the command.

Use the field ID from `get_fields` exactly as listed and refresh the list after editing the login. Fields marked
`private`, including passwords, TOTP seeds, and hidden custom fields, require `--allow-private`. The flag prevents
accidental disclosure. Privacy follows the field type, so ordinary fields such as notes can still contain secrets.
For a private value, add the flag only when piping the value directly into the intended command's stdin.
Running that command on its own can expose the value in the terminal or agent transcript. See the
[Vaultkeeper CLI skill](skills/vaultkeeper-cli/SKILL.md) for a pipeline example.

## Project layout

Cargo workspace (Rust edition 2024):

| Path | Purpose |
|---|---|
| `app/` | The `vaultkeeper` binary: Slint UI, tray, daemon and UI processes, hotkeys, auto-type |
| `crates/api` | HTTP client and wire models for the Bitwarden/Vaultwarden API |
| `crates/crypto` | Bitwarden-compatible key derivation and `EncString` crypto |
| `crates/gen` | TOTP codes and password/passphrase generation |
| `crates/ipc` | Daemon to UI process IPC over a local socket, including peer verification |
| `crates/platform` | OS integration: keychain, Touch ID, autostart, clipboard, single instance, hardening |
| `crates/ssh` | SSH agent adapter over the vendored `ssh_agent` |
| `crates/vault` | Session state, encrypted cache, decrypted views and vault operations |
| `vendor/ssh_agent` | Vendored from Bitwarden's clients repository, with patches listed in `vendor/PATCHES.md` |
| `vendor/secure_memory` | Vendored from Bitwarden's clients repository |

## Development

```sh
scripts/check.sh    # cargo fmt --check, clippy with -D warnings; also the pre-commit hook in .githooks
SLINT_BACKEND=winit-software cargo test --workspace
scripts/e2e.sh      # end-to-end tests against Docker Vaultwarden + Mailpit
```

`scripts/e2e.sh` starts a disposable Vaultwarden and Mailpit with Docker Compose, runs the vault scenarios and then the
app's own, which start a real daemon process and drive it over IPC. Docker is required.

## Security notes

- Secrets are decrypted on demand and handed out as zeroizing values; only names and other list data are decrypted at
  unlock.
- The vault cache on disk is encrypted. Refresh tokens are kept in the macOS login keychain.
- The daemon and UI process talk over a Unix socket with mode 0600. The daemon checks the peer's uid and code signature
  (audit token plus `SecCode`) and accepts only a UI process with its own signature.
- Release bundles are signed with the hardened runtime, so other processes cannot inject code into them.

Design and threat model: [docs/solutions/vaultkeeper-architecture.md](docs/solutions/vaultkeeper-architecture.md).
Vaultkeeper has not had an independent security audit.

## Roadmap: cross-platform

This is a plan. Nothing here is implemented yet; today Vaultkeeper runs on macOS only.

Already portable: Slint, `reqwest` with rustls, and the `crypto`, `api`, `gen` and `vault` crates. `crates/platform` already
compiles on other targets and returns `Unsupported` errors there.

macOS-specific code, found with `grep -rn 'target_os = "macos"' --include=*.rs`:

| Area | Where |
|---|---|
| Swift shim for Secure Enclave / Touch ID, power and network events | `crates/platform` (`biometric`, `power`, `network`, `build.rs`, `swift/`) |
| Keychain (`security-framework`), clipboard concealment, LaunchAgent autostart, paths, hardening | `crates/platform` |
| AppKit activation policy, auto-type via CGEvent, biometrics glue | `app/src/os` |
| IPC peer check (audit token + `SecCode`) | `crates/ipc/src/peer.rs` |
| SSH agent peer info | `vendor/ssh_agent/src/server/peer_info.rs` |

Phases:

1. **Platform traits.** Put each platform service (secret storage, biometrics, autostart, clipboard, hotkeys, auto-type,
   IPC peer check, power and network events) behind a trait, with the macOS implementation first and no behavior change.
2. **Linux.**
   - Refresh tokens in Secret Service (libsecret).
   - Autostart through a freedesktop `.desktop` file.
   - IPC peer check with `SO_PEERCRED` plus an executable check.
   - Clipboard and global hotkeys for X11 and Wayland (Wayland support varies by compositor).
   - Biometrics through polkit/fprintd, or none.
   - The Unix-socket SSH agent already works.
3. **Windows.**
   - Credential Manager or DPAPI for tokens, Windows Hello for biometrics.
   - IPC over named pipes with a client process check.
   - The Windows OpenSSH agent named pipe.
   - Autostart through the registry Run key, auto-type through `SendInput`.
4. **CI and packaging.** A CI matrix for macOS, Linux and Windows, then packages: dmg, AppImage or Flatpak, MSI.

## License

GPL-3.0-only, see [LICENSE](LICENSE). The `ssh_agent` and `secure_memory` crates under `vendor/` are vendored from
Bitwarden's GPL-licensed clients repository (upstream commit recorded in `vendor/UPSTREAM.txt`); Vaultkeeper stays under the
same license.
