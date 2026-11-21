# Linux test checklist

Manual checks for the Linux port (docs/solutions/linux-plan.md, step 7a). Each section names the plan steps it covers and the VMs to run it in.


Manual checks that need a real session, one section per risk; run in the four VMs (each driven through its MCP): **`vm-fedora-gnome`** (Fedora 45 Workstation, GNOME 51, UEFI + Secure Boot), **`vm-kubuntu`** (Kubuntu 26.10, Plasma 6.7.5; optional `apt install sway` session), **`vm-fedora-sway`** (Fedora 45 Sway Spin: Waybar, swaylock/swayidle, lxqt-policykit), **`vm-omarchy`** (Omarchy v4.5.0: Arch, Hyprland 0.57.2, Omarchy shell, UWSM, Limine UKI, btrfs + LUKS, Secure Boot off, Chrome). Run as a normal user with the release tarball of the commit under test installed through the tap (`brew install avbel/tap/vaultkeeper`). Each section names its VMs; "all" = the four. Not covered by this set: Ubuntu GNOME (run the GNOME sections once in a GNOME session added to `vm-kubuntu` with `ubuntu-desktop-minimal`) and Fedora KDE (untested; Plasma is covered at 6.7.5 on Kubuntu). Record per run: `uname -r`, `cat /sys/kernel/security/lsm`, `cat /sys/kernel/security/lockdown`, `mokutil --sb-state`, `echo $XDG_SESSION_TYPE $XDG_CURRENT_DESKTOP`, desktop version, `vaultkeeper --version`, `vaultkeeper security status`. Tick a line only after the expected result; paste `security status` tables and the spike numbers into the PR.

### 0. Setup (all)
- [ ] Record the VM: `vm-fedora-gnome` / `vm-kubuntu` / `vm-fedora-sway` / `vm-omarchy`; on Omarchy also `omarchy-version`, `omarchy kernel`, `pacman -Q linux-omarchy hyprland xdg-desktop-portal-hyprland quickshell google-chrome`.
- [ ] Wayland session (`XDG_SESSION_TYPE=wayland`); `XDG_RUNTIME_DIR` is `/run/user/<uid>` on tmpfs, mode 0700.
- [ ] Homebrew installed at `/home/linuxbrew/.linuxbrew`; `brew install avbel/tap/vaultkeeper`; caveats list the runtime packages and the BPF command.
- [ ] First start writes `~/.local/share/applications/io.github.avbel.Vaultkeeper.desktop` and icons; the launcher shows "Vaultkeeper" with its icon.
- [ ] One login saved, CLI access on, one login allowed for CLI; a FIDO2 key; Firefox (snap on Ubuntu, rpm on Fedora) and Chrome installed.

### 1. Baseline gate (1c) — all; the per-distro fix text on each
- [ ] `vaultkeeper security status` shows every chain with a status and the active link; no refusal on a stock install.
- [ ] Break the data dir (`chmod 755 ~/.local/share/vaultkeeper`): start repairs it and logs a warning. Replace it with a symlink: start refuses with the window (desktop launch) or the table and exit 78 (terminal).
- [ ] `vaultkeeper --skip-security-issues` starts with the warning badge; `vaultkeeper security accept` then lets autostart proceed; a new issue (e.g. `WAYLAND_DISPLAY` unset in a terminal) refuses again.
- [ ] Fedora (Yama 0) without BPF: C3 shows "Reduced" with the ptrace_scope/BPF hint; Ubuntu shows "Standard".

### 2. Hardening and sandbox (1d, 1e, 1f) — all
- [ ] `cat /proc/<daemon pid>/status | grep -i dumpable`-equivalent: `ls -l /proc/<pid>/exe` as the same user fails (EACCES) for daemon, UI, CLI after the handshake.
- [ ] `gdb -p <daemon pid>` as the user fails; `sudo gdb -p` works (root is out of scope).
- [ ] "Keys in memory" shows `memfd_secret`; `grep SecretMem /proc/meminfo` is non-zero while the daemon runs and the vault is unlocked (the vault's user and organization keys and the SSH agent's keys rest encrypted under a memfd_secret key). `mseal` is not used: the store frees its page on drop.
- [ ] Landlock is opt-in until this section passes: start with `VAULTKEEPER_LANDLOCK=1 vaultkeeper` and check the log line `sandbox status=Landlock fully enforced` (or partly, with the kernel's ABI). Then the daemon cannot read `~/Documents` or `~/.ssh`; fonts, GPU, portals, tray and D-Bus still work on all four desktops; `brew upgrade` followed by a restart still starts the new binary. MDWE on: no crash in Slint/Mesa (else record and flip decision 11). When all four VMs pass, Landlock becomes the default.
- [ ] UI runs under the same ruleset (it inherits it). File dialogs: exporting an attachment to `~/Downloads` and importing from `~/Documents` are expected to fail under the current rules (the portal returns real paths outside the allowed directories); record the behaviour, so the rule set or the dialog handling can be chosen.

### 3. App id and portals (3a) — `vm-fedora-gnome`, `vm-kubuntu`, `vm-omarchy`
- [ ] GNOME/KDE GlobalShortcuts dialog and the RemoteDesktop prompt show "Vaultkeeper" with the icon, not the binary name.
- [ ] After `killall xdg-desktop-portal` the app re-registers and portal calls work again.

### 4. Hotkeys (3b) — all (GNOME: `vm-fedora-gnome`; KDE and Sway: `vm-kubuntu`; Sway: `vm-fedora-sway`; Hyprland: `vm-omarchy`)
- [ ] GNOME: Ctrl+Shift+Space opens the Quick Panel on first use after the one-time binding dialog; Settings shows the trigger text and "Change in system settings…" opens the GNOME dialog.
- [ ] KDE 6.7.5 and 6.8.1: same; rebinding in System Settings → Shortcuts is reflected in Vaultkeeper's Settings.
- [ ] Hyprland (`vm-omarchy`): `o.bind("CTRL + SHIFT + SPACE", "Vaultkeeper", "vaultkeeper --search")` in `~/.config/hypr/bindings.lua` works; the xdph GlobalShortcuts route works too (record which); Settings shows the Lua line on Omarchy and the `bind =` line elsewhere.
- [ ] Sway: `bindsym Ctrl+Shift+space exec vaultkeeper --search`; Settings shows the exact line with a copy button.
- [ ] Generator hotkey the same; AltGr warning appears for Ctrl+Alt+<key> on Linux; the recorder hint says "Ctrl, Alt or Super".

### 5. Quick Panel focus (3c) — all
- [ ] GNOME: the panel has keyboard focus immediately (token path).
- [ ] KDE: focus without a token at the default focus-stealing level; record the level where it fails and whether the live-UI token fallback fixes it.
- [ ] Sway and Hyprland: new window focused; typing goes to the search field.
- [ ] Closing the panel returns focus to the previous window.

### 6. Clipboard (3d) — all
- [ ] KDE, Sway, Hyprland: copy a password; `wl-paste -l` lists `x-kde-passwordManagerHint`; KDE Klipper (`vm-kubuntu`) and the Omarchy clipboard panel (`vm-omarchy`, Super+Ctrl+V) do not record it; the clear timer empties it.
- [ ] GNOME: one RemoteDesktop/Clipboard permission prompt, persisted across restarts (`restore_token`); copy works afterwards without a prompt; GNOME clipboard-history extensions (if installed) behaviour recorded.
- [ ] Deny the GNOME prompt: C8 shows "Reduced", copying still works through arboard, with the clear timer.

### 7. Tray (3e) — `vm-kubuntu` (Plasma), `vm-fedora-sway` (Waybar), `vm-omarchy` (Omarchy shell bar), `vm-fedora-gnome` (extension)
- [ ] KDE: icon in the system tray, menu works, click opens the Quick Panel; theme Auto follows light/dark.
- [ ] `vm-fedora-sway` Waybar `tray` module and `vm-omarchy` shell bar: icon shows, menu works, click opens the Quick Panel.
- [ ] GNOME with the AppIndicator extension (Ubuntu default; Fedora after `dnf install gnome-shell-extension-appindicator`): icon shows; without it: Settings shows the "no tray" notice and the hotkey/launcher still work.

### 8. Lock, sleep, session end (3f) — all (Omarchy: its shell lock + `omarchy-sleep-lock.service`; Sway spin: swayidle/swaylock)
- [ ] Lock the screen (Super+L / `loginctl lock-session`): vault locks when "Lock on sleep or screen lock" is on. GNOME, KDE, swaylock (via swayidle `lock` hook calling `loginctl lock-session`), hyprlock likewise.
- [ ] Suspend/resume: locked on resume. Log out: the daemon exits cleanly (`PrepareForShutdown`/session end), no stale sockets in `$XDG_RUNTIME_DIR/vaultkeeper`.

### 9. Autostart (3g) — all
- [ ] GNOME, KDE and `vm-omarchy` (UWSM): "Start at login" on writes `~/.config/autostart/io.github.avbel.Vaultkeeper.desktop` with `Exec=<opt path> --tray`; reboot → tray present; off → file removed. Switching it off in the desktop's own startup settings (it writes `Hidden=true`) shows as off in Vaultkeeper.
- [ ] `vm-fedora-sway` and the Kubuntu Sway session (stock config): the autostart file has no effect there; record it, and whether the Background portal or a systemd user unit is needed (chain C11 links 1–2 are not built yet).
- [ ] The autostart command never contains `--skip-security-issues`.

### 10. Auto-type (3i) — `vm-fedora-gnome`, `vm-kubuntu` (portal); `vm-omarchy`, `vm-fedora-sway` (virtual keyboard)
- [ ] GNOME and KDE: first use prompts once (RemoteDesktop keyboard); typing into gedit/kate works, including non-ASCII; the session persists across restarts.
- [ ] Sway/Hyprland: virtual-keyboard route types into foot/kitty; record layout issues.

### 11. Quick unlock (3j) — hardware gate; `vm-kubuntu` and `vm-omarchy` with the FIDO2 key passed through
- [ ] FIDO2: enrol with the key (PIN or UV prompt), lock, unlock by touching the key; wrong key → "enrol again"-free `BiometricFailed`; key removed → master password works.
- [ ] fprintd (laptop or `fprintd` virtual device): "Fingerprint unlock (key stays in memory)" verifies; after a daemon restart the master password is required (as documented).
- [ ] SSH approval with "requires security key/fingerprint" prompts and signs; cancel denies.

### 12. Homebrew lifecycle (6b, 6c, 2e) — `vm-kubuntu`, `vm-fedora-gnome`, `vm-omarchy` (first Homebrew-on-Arch run: record the installer output)
- [ ] `brew install`: `vaultkeeper --version` prints `install: homebrew`; Settings shows "Updates: managed by Homebrew", no "Check for Updates…" in the tray; no request to api.github.com in the log.
- [ ] `brew upgrade` (publish a test release or `brew reinstall` a different version) while the daemon runs: CLI says "Vaultkeeper was updated"; tray offers "Restart to finish the update"; the daemon restarts itself when locked; the new binary runs; with BPF installed: "this build is not enrolled → Enroll…" appears and enrolment prompts for the admin password once.
- [ ] `brew uninstall`: daemon stops on next `--quit`; user data stays; `brew install` again finds it.

### 13. BPF protection (4a–4c) — `vm-fedora-gnome` (Secure Boot on and off), `vm-kubuntu`, `vm-omarchy` (SB off, lockdown none); `vm-fedora-sway` for the enrol prompt through lxqt-policykit
- [ ] `sudo vaultkeeper security install`: Fedora and Omarchy (btrfs) succeed at once; Kubuntu (ext4 without `verity`): prints the `tune2fs -O verity` command, after reboot `install` succeeds; `cat /sys/kernel/security/lockdown` shows `[integrity]` with SB on (Fedora), `[none]` otherwise (Omarchy always); programs load in every case.
- [ ] `vaultkeeper security verify` and Settings show "BPF protection: active · enforcing · this build enrolled"; the canary self-test is denied.
- [ ] As the user: `cat ~/.local/share/vaultkeeper/accounts/*/refresh_token.enc` → Permission denied; `mv`/`rm` of the data dir denied; `sudo cat` works.
- [ ] `gdb -p <pid>`, `cat /proc/<pid>/mem`, `process_vm_readv` tool, `pidfd_getfd` tool → denied even with `ptrace_scope=0` (Fedora) and even for a dumpable test build.
- [ ] `kill -STOP <pid>` and `pkill vaultkeeper` denied; `vaultkeeper --quit`, `systemctl --user stop io.github.avbel.Vaultkeeper` (when the unit route is used), Ctrl+C in a CLI call all work.
- [ ] `socat - UNIX-CONNECT:$XDG_RUNTIME_DIR/vaultkeeper/cli.sock` denied; a pre-bound impostor socket at that path is denied (`socket_bind`); `ssh-add -l` against `ssh.sock` works.
- [ ] A copied binary (`cp vaultkeeper /tmp/vk && /tmp/vk`) is treated as foreign: no key file access, refused by the daemon's socket.
- [ ] `openat` micro-benchmark before/after `load`: record µs per open for `/etc/passwd` and for a protected file as root.
- [ ] `sudo systemctl stop vaultkeeper-bpf`: everything allowed again immediately; `start` re-enforces; survives reboot; `uninstall` removes unit, D-Bus files, policy, pins.
- [ ] Settings "Enroll…" after an upgrade shows the polkit dialog (not pkexec), works under the Landlock ruleset.

### 14. Browser integration (5a–5d) — `vm-kubuntu` (Firefox snap, Chrome .deb), `vm-fedora-gnome` (Firefox rpm), `vm-omarchy` (Chrome default, omarchy-chromium)
- [ ] Ubuntu Firefox snap: with `widget.use-xdg-desktop-portal.native-messaging-proxy=1` the extension connects through the proxy; Settings identifies "Firefox"; without the pref the Settings notice explains it.
- [ ] Fedora Firefox rpm: direct manifest in `~/.mozilla/native-messaging-hosts` works; the host identifies Firefox by path.
- [ ] Chrome (.deb on Kubuntu; Omarchy default): manifest in `~/.config/google-chrome/NativeMessagingHosts`; the host identifies `/opt/google/chrome/chrome`; fill, save prompt, TOTP copy, passkey create/sign (UV via the FIDO2 chain). Omarchy `omarchy install browser chromium` (omarchy-chromium-bin): `~/.config/chromium/…` manifest and identification work.
- [ ] "Hardened runtime" status row is green only when `is_hardened()` holds; with BPF the browser socket refuses a foreign client.

### 15. Omarchy kernel and configuration swaps (`vm-omarchy`) — the probes must decide, never a default
- [ ] Stock `linux-omarchy` 7.2.15: `security status` shows Landlock ABI 10 (C6 Full), BPF available, memfd_secret, lockdown none; record `cat /sys/kernel/security/lsm` and `zcat /proc/config.gz | grep -E 'CONFIG_LSM=|BPF_LSM|FS_VERITY|SECRETMEM'`.
- [ ] `sudo pacman -S linux-lts && sudo omarchy kernel set linux-lts`, reboot: kernel 6.18 → C6 "Reduced" (ABI 7) with the exact text; everything else unchanged (PIDFD_GET_INFO, memfd_secret; BPF only if `bpf` is in that kernel's LSM list — record `CONFIG_LSM`).
- [ ] `sudo pacman -S linux-hardened && sudo omarchy kernel set linux-hardened`, reboot: record `CONFIG_LSM`, Yama scope, `kernel.unprivileged_userns_clone`; the chains degrade or refuse with named items; `--skip-security-issues` starts the app; `security accept` persists for autostart. Switch back to `linux-omarchy`.
- [ ] Remove `bpf` from `lsm=` through a `/etc/limine-entry-tool.d/` drop-in + `omarchy-refresh-limine`, reboot: the BPF row says "unsupported — lsm list lacks bpf" with the Omarchy fix text; restore.
- [ ] Kill the Omarchy shell (`pkill quickshell`): tray row → "no tray"; the enrol action reports "no polkit agent in this session"; `omarchy-launch-shell` and "Re-check" recover both rows.
- [ ] Homebrew on Omarchy: the brew installer runs with the stock packages; `brew install avbel/tap/vaultkeeper` works.

### 16. Memory and startup — all
- [ ] `scripts/measure-linux.sh`: daemon tray-only, UI with the Quick Panel, UI 10 s after close; compare with macOS (13.9 / 47.3 / 41.8 MB).
- [ ] Cold start to tray < 1 s; `security status` probes < 50 ms (printed in the log).
