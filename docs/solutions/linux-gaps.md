# Vaultkeeper on Linux: state and open holes

Date: 2026-11-20. Delta against [linux-support.md](linux-support.md) (research of 2026-11-13); section numbers like §5.1 refer to that doc. The research that follows from these gaps is in [linux-ideas.md](linux-ideas.md), and the development plan is in [linux-plan.md](linux-plan.md).
Marks: **[v]** = checked today in code, in a build or in a primary source; **[s]** = secondary source only; **[i]** = inferred, check on a real machine.

## 0. Short answers

| Question | Answer |
|---|---|
| Does it build for Linux? | Almost. Every library crate type-checks; the `vaultkeeper` crate fails with 3 errors (§1). The binary and its tests were not reached, so more may follow. |
| What would run after those fixes? | Nothing past login: `store_login_secrets` (`crates/vault/src/vault/session.rs:397-410`) propagates the keychain's `Unsupported`, so adding an account fails [v: code]. With `SealedFileStore` wired: vault, sync, Manager and Quick Panel windows, CLI, SSH agent socket, a pixmap tray icon [i]. Everything else hits an `Unsupported` stub (§3). |
| Linux code so far? | None of its own: `target_os = "linux"` appears only in `vendor/secure_memory`. The Windows port left a fallback for every OS hook, which is why it nearly builds. |
| Biggest new findings | Portal app-id registration is now mandatory (§4.1); GNOME has no data-control at all, so the daemon cannot own the clipboard there (§4.2); browser integration is blocked off macOS/Windows by the hardening gate (§3). |
| AppImage? | As a later, reduced tier only (§5). |

## Decisions (2026-11-20, user)

- **Scope.**
  - Distributions: only the latest Ubuntu, the latest Fedora and Arch (rolling).
  - Session: Wayland only.
  - Desktops: only GNOME, KDE Plasma, Sway and Hyprland, at the versions those distributions ship.
  - Out: Debian, other desktops, X11, and fallbacks for older releases (GNOME 46 / Ubuntu 24.04).
  - **Arch is supported as the Omarchy build only** (latest Omarchy, Hyprland), because plain Arch has no default security configuration: every user assembles their own kernel, `lsm=` list, polkit agent, portals and tray host.
    - Omarchy's defaults are the supported Arch configuration and the test target.
    - Other Arch setups are unsupported. They run only if the startup probes of the security chains pass; otherwise the app refuses with an exact message (unless `--skip-security-issues`).
    - Nothing is assumed from distro defaults on any distribution; the probes decide.
- **Test VMs.** Fedora with GNOME; Kubuntu (KDE, with an optional Sway session); Fedora Sway Spin; Omarchy (Arch with Hyprland).
- **Distribution.** Homebrew first, through the user's tap (`avbel/homebrew-tap`, prebuilt release tarballs like `Formula/yrem.rb`). .deb and .rpm come next. AppImage is not planned.
- **Auto-update.** The existing "Update automatically" setting (`auto_update`) stays for direct installs. When a package manager installed the app (Homebrew, later deb/rpm), it is off and disabled or hidden, and so is "Check for Updates…".
- **Security chains.** Each protection is a chain of mechanisms, strongest first: if feature 1 is missing, use 2, and so on. Mechanisms that stack are layered. `vendor/secure_memory` (memfd_secret → keyctl → mlock) is the pattern.
- **BPF LSM now, not later.** The hardened mode of `linux-support.md` §5.6 becomes the first link of the chains it serves:
  - file access to the key and data dir;
  - ptrace and memory reads;
  - signals;
  - connects to the daemon socket.

  The binary is identified by a signed fs-verity digest, which also covers the user-writable Homebrew prefix. A one-time privileged install loads it, since Homebrew has no root.
- **Show the security solution in use.** The Settings dialog shows which mechanism protects each area, as a summary line plus a Security section listing every chain with its active link (plan step 3l).
- **Mandatory baseline.** The app refuses to start when no link of a required chain works, unless it is run with `--skip-security-issues`.
- **Hotkeys as on Windows.** Quick Panel defaults to Ctrl+Shift+Space, and in-app shortcuts and labels are Ctrl-based. Today's `cfg(not(windows))` arms (`app/src/settings.rs:374`, `hotkey_recorder.rs:20-26`, `settings_hotkeys.rs:55-82`) give Linux the macOS values.

## 1. Build check

Run: `rust:1.99.1-bookworm` (arm64) in Docker, with `libfontconfig1-dev libxkbcommon-dev libwayland-dev libdbus-1-dev libudev-dev`, `cargo check --workspace --all-targets --locked --keep-going`. **[v]**

| Location | Error | Cause |
|---|---|---|
| `app/src/os/mod.rs:68` | E0308, expected `Arc<dyn DockIcon>`, found `()` | `dock` has macOS and Windows arms only |
| `app/src/os/mod.rs:87` | E0308, expected `Arc<dyn WindowPlacement>`, found `()` | `placement` has macOS and Windows arms only |
| `app/src/daemon/update/mod.rs:292` | E0599, no `zip_path` on `Installer` | `download_and_stage` is `cfg(not(windows))`, so it assumes macOS; `install_unavailable.rs` has no `zip_path` |
| `crates/platform/src/autostart.rs:15` | warning, `TRAY_ARG` unused | Unix arm without a Linux implementation |

There is no Linux job in `ci.yml` and no Linux artifact in `release.yml`, so these regressions went unnoticed.

## 2. Done since 2026-11-13 that Linux can reuse

| Item | Where | Remaining Linux work |
|---|---|---|
| Sealed token store of §5.1, with an optional `BlobWrapper` (DPAPI on Windows) | `crates/vault/src/sealed_store.rs` | `app/src/daemon/secrets.rs:70` still picks `KeychainStore` for every non-Windows target; wire `SealedFileStore` (no wrapper, or a `systemd-creds` wrapper) |
| Startup permission check hook | `crates/platform/src/fs.rs:75-99`, `app/src/os/startup_check.rs` | Unix arms are no-ops; add owner, symlink, ACL and runtime-dir checks (§5.4) |
| `vaultkeeper --search` and `--generator` (d20f31b) | CLI | Covers the Sway `bindsym` and GNOME 46 custom-shortcut fallbacks of §7.1 |
| Tray icon choice Auto / White / Black / Blue | `app/src/settings.rs:24` | Auto on Linux still needs a symbolic icon name (§4) |
| `biometric-*` properties and `BIOMETRIC_LABEL` | `app/ui/*.slint`, `app/src/os/biometrics.rs:18` | Add the "system authentication" label |
| Ed25519 release-signature check | `app/src/daemon/update/signature.rs` | Usable for an AppImage self-update |

## 3. Stubs: compile, do nothing on Linux

| Area | Where | On Linux today | Plan |
|---|---|---|---|
| Token storage | `crates/platform/src/keychain.rs` via `daemon/secrets.rs:70` | `Unsupported`, and login fails with it (§0) | `SealedFileStore` (§2) |
| Clipboard | `crates/platform/src/clipboard.rs:48,110` | `Unsupported` | data-control via `wl-clipboard-rs` on KDE, Sway, Hyprland; GNOME needs another design (§4.2) |
| Global hotkey | `global-hotkey` 0.9, X11 only | Grabs nothing under Wayland [i] | GlobalShortcuts portal plus `Registry.Register` (§4.1) |
| Auto-type | `app/src/os/autotype.rs:101-163` | No frontmost app, `Unavailable` | RemoteDesktop portal, virtual keyboard (§7.4) |
| Quick unlock | `crates/platform/src/biometric.rs:67-128` | `false` / `Unsupported` | polkit (§3.2). The current API enrolls a hardware-wrapped key file (`enroll(path, user_key)`); Linux keeps the key in memory, so it needs a second shape |
| Autostart | `crates/platform/src/autostart.rs:517-531` | `Unsupported` | XDG autostart or Background portal (§7.5) |
| Lock and sleep | `crates/platform/src/power.rs:81` | `Unsupported` | logind and ScreenSaver (§7.2) |
| Network change | `crates/platform/src/network.rs:67` | `Unsupported` | NetworkManager or the existing probe |
| Open links | `app/src/os/misc.rs:123` | `Unavailable` | OpenURI portal or `xdg-open` (not in the 11-13 doc) |
| File dialogs | `app/src/os/misc.rs:155-170` | `None`; `rfd` is not a Linux dependency | `rfd` with `xdg-portal` (§7.10) |
| Updater | `app/src/daemon/update/install_unavailable.rs` | Links to the release page | Fine for packages; AppImage only later |
| Process hardening | `crates/platform/src/hardening.rs:18-27` | `RLIMIT_CORE=0` only | `PR_SET_DUMPABLE(0)`, `umask(077)` (§5.4) |
| Window focus | none | No xdg-activation token is passed to the UI process | §6 |
| App id | none | No Wayland `app_id`; Slint's tray id is hardcoded `"slint-tray"` [v: `i-slint-core-1.19.0/items/system_tray/ksni.rs:40`] | §7.9 |
| Tray icon | Slint 1.19 `ksni` | Still `icon_pixmap` only, no icon name [v: same file, line 62] | `ksni` directly (§4) |
| Browser integration | `app/src/browser_status.rs:31-40` | **Blocked**: `runtime_hardened()` falls through to `has_hardened_runtime()`, which is `false` off macOS | A Linux gate, such as "`PR_SET_DUMPABLE` applied", in the way Windows uses the process DACL |
| Browser manifests | `app/src/daemon/browser/manifests.rs` | macOS layout under `data_dir.parent()`, so files land in `~/.local/share/Google/Chrome/…`, which no browser reads | `~/.config/{google-chrome,chromium,BraveSoftware/Brave-Browser,microsoft-edge}/NativeMessagingHosts`, `~/.mozilla/native-messaging-hosts`, Flatpak dirs under `~/.var/app/` (Bitwarden's `desktop_native/core/src/ipc/mod.rs` lists them) |
| Browser identity | `app/src/browser_host/parent.rs:64` | `identify_browser` returns `None` | No code signature to check; pairing is the only gate |
| Passkeys | `app/src/daemon/browser/dispatch.rs:505` | Off: needs `touch_id_available()` | Comes with polkit quick unlock |
| Security keys | `authenticator` crate (USB HID) | Compiles; needs hidraw access [i] | Rely on the distro's FIDO udev rules; document |
| SSH agent socket | `app/src/os/layout.rs:97-107` | In the data dir (`~/.local/share/vaultkeeper/`) | `$XDG_RUNTIME_DIR/vaultkeeper/` (§1) |

## 4. New holes (not in the 11-13 doc)

### 4.1 Portal app id is mandatory

xdg-desktop-portal 1.20+ serves app-id-gated portals to a non-sandboxed app only after it calls `org.freedesktop.host.portal.Registry.Register(app_id, {})`. The id must match the basename of an installed `.desktop` file, the call must come before any other portal call, it can be made once only, and it must be repeated when the portal restarts (`NameOwnerChanged`). The rules of the call are from the portal's Registry docs [v]. That the older systemd-scope detection no longer yields an app id, so `GlobalShortcuts.CreateSession` fails with "An app id is required" on GNOME 50 / Fedora 44, comes from one bus trace in electron/electron#51875 [s]; calling `Register` is right either way. This resolves open risk 4 of §8 and makes open decision 2 (the app id) a blocker for hotkeys, auto-type and autostart through portals.

### 4.2 GNOME has no data-control

The wayland.app compositor table for `ext-data-control-v1` lists Mutter 51 as unsupported, next to KWin 6.7, Sway 1.11 and Hyprland 0.57.2 as supported [v]. Mutter's `src/wayland` on main (commit 9bc8cd8, 2026-11-19) has no data-control file [v]. The "ext-data-control from GNOME 49 [i]" cell of §2 was wrong (now corrected); secondary sources disagree [s]. On every GNOME version, the windowless daemon can neither set nor clear the clipboard. A copy has to come from a focused UI window, and auto-clear needs another route: the RemoteDesktop portal clipboard (Bitwarden's way, with a consent dialog and a remote-control indicator), or a clear done by a UI window. This is the largest UX gap on the biggest desktop.

### 4.3 Features added after the doc

| Feature | Linux counterpart |
|---|---|
| Browser extension: pairing, fill, save, password generation, remembered logins, autofill on page open | Needs the hardening gate, the Linux manifest dirs and Flatpak/Snap browser handling (§3) |
| Passkeys | After polkit |
| Quick Panel / generator from the CLI | Works as the hotkey fallback; auto-type has no "app that was in front" to return to |
| Windows Hello, SSH named pipes, DPAPI | Not applicable |

## 5. Packaging: AppImage

An AppImage remounts itself at a new `/tmp/.mount_XXXX` on every launch, so `current_exe()` changes each time. This breaks three things:

- Browser manifests that render `exe()`.
- The autostart `Exec=` line.
- `SameExecutable` (`crates/ipc/src/peer.rs:150`, path compare). A CLI call, a compositor-bound `vaultkeeper --search` or a browser-spawned host runs in another mount, so the daemon rejects it. Comparing (st_dev, st_ino) instead, as §7.6 proposes, does not help, because each FUSE mount has its own device.

KeePassXC has the manifest variant open (#13577, Aug 2026). Bitwarden copies its small `desktop_proxy` into each browser's `NativeMessagingHosts` dir; Vaultkeeper's host is the full binary.

The mount is also `nosuid`, so there is no setgid persistent mode (§5.5). The polkit policy needs a `pkexec` install, the app must write its own `.desktop` file for §4.1, and the classic runtime needs libfuse2, which stock Ubuntu 24.04 and Fedora 44 Atomic lack (use the static type2 runtime) [s]. Its one advantage: it is the only format the signed self-updater can replace in place.

Recommendation: .deb, .rpm and AUR first. Ship an AppImage only later, and make it copy itself to `~/.local/lib/vaultkeeper/` on first run and point every written path at that copy. Superseded by the user's decision: Homebrew first, then .deb and .rpm (see Decisions). Several AppImage problems recur under Homebrew: the binary sits in a user-writable prefix, there is no root for the polkit policy or setgid, the app must write its own `.desktop` file, and `brew upgrade` moves the binary to a new `Cellar/<version>` path.

## 6. Security holes (Linux weaker than macOS and Windows)

1. **Peer check by pid.** `crates/ipc/src/transport/unix.rs:180` takes the pid from `SO_PEERCRED`, then `peer.rs:213` reads `/proc/<pid>/exe` by path. A pid can be recycled between connect and check, which the macOS audit token rules out. Use `SO_PEERPIDFD` (kernel 6.5+) and compare (st_dev, st_ino). It stays a guard against mistakes, not a boundary (§7.6).
2. **No `PR_SET_DUMPABLE`.** Without it, a same-uid process may read the user key from daemon memory wherever Yama's `ptrace_scope` is 0 [i: distro defaults differ].
3. **No startup permission checks** on Unix (§3).
4. **2FA-remember token.** Once `SealedFileStore` is wired with no wrapper, it sits wrapped by nothing, in a 0600 file (open decision 3).
5. **Daemon socket.** Any same-uid process can use the CLI and socket while the vault is unlocked; the per-request confirmation of §5.5 is not built.
6. **Browser identity** is not verifiable (§3). Pairing is the only gate.
7. **Package upgrade under a running daemon** [i]. The daemon builds its verifier once (`crates/ipc/src/cli_access.rs:84`), but each client checks the daemon on every call (`cli_access.rs:212`). After `apt`/`dnf` replaces `/usr/bin/vaultkeeper`, the old daemon's `/proc/<pid>/exe` reads `… (deleted)`. New CLI, UI and browser-host processes then reject it, and spawning a UI from the daemon's own path may fail, until the daemon restarts. With the (st_dev, st_ino) compare of item 1, the daemon would also reject the new clients. Mitigation: the package's postinst restarts the user daemon, or the daemon restarts itself when its binary is replaced.

## 7. Status of the §8 open risks

| # | Risk | Status |
|---|---|---|
| 1 | xdg-activation tokens | Open; no code yet |
| 2 | GNOME data-control | Answered: none in Mutter up to 51 [v]. Still open: what GNOME does with a copied secret after the owning process exits |
| 3 | GNOME top-bar colour, symbolic names | Open |
| 4 | Portal app id for a non-Flatpak binary | Answered: `Registry.Register` (§4.1) [v] |
| 5 | polkit without an agent, pam_fprintd | Open |
| 6 | Firefox Snap native messaging | Partly: Ubuntu's Firefox snap has used a WebExtensions portal since 2022 [s]; whether it starts Vaultkeeper's host is untested. The host's parent would then be the portal, not Firefox |
| 7 | First GNOME with GlobalShortcuts | GNOME 48 [s: GNOME Discourse] |

Open decision 1 (support floor) changes shape. Raising the floor to GNOME 48+ still buys the GlobalShortcuts portal, but no GNOME version gives data-control. So the GNOME clipboard fallback of §4.2 is needed whatever the floor.

## 8. Suggested order

1. Fix the 3 compile errors and add a Linux CI job (`cargo check`, `clippy`, unit tests on `ubuntu-latest`), so Linux stops regressing.
2. Wire `SealedFileStore`, `PR_SET_DUMPABLE`, the Unix startup checks and the runtime-dir sockets.
3. Choose the app id; `Registry.Register`, `.desktop` file, Wayland `app_id`.
4. Clipboard: data-control for KDE, Sway and Hyprland, plus the GNOME design (§4.2).
5. Tray through `ksni`, hotkey portal, lock/sleep, autostart, the Homebrew formula (then `.deb`/`.rpm`).
6. Browser integration: Linux gate, manifest dirs, Flatpak/Snap.
7. polkit quick unlock, auto-type, AppImage.
