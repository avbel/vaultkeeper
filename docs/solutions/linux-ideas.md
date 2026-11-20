# Vaultkeeper on Linux, latest-only: ideas to close the gaps

Date: 2026-11-20. Written against `docs/solutions/linux-gaps.md` (gaps) and `docs/solutions/linux-support.md` (design). Section numbers "gaps §x" and "design §x" refer to those files.
Marks: **[v]** checked in a primary source or in code (cited), **[s]** secondary source, **[i]** inferred; check on a real machine.
Scope and decisions of 2026-11-20 (gaps "Decisions"): latest Ubuntu + latest Fedora only, Wayland only, GNOME / KDE Plasma / Sway / Hyprland only; Homebrew first; BPF LSM now; mandatory baseline with `--skip-security-issues`; Windows-style hotkeys. Later the same day: Arch returned, but only as the **Omarchy build** (latest Omarchy = Arch + Hyprland); plain Arch runs only if the probes pass. Four test VMs (Fedora GNOME with Secure Boot, Kubuntu + optional Sway, Fedora Sway Spin, Omarchy) are mapped to every check and open question. Sections 7–12 cover the requirements; the development plan is `linux-plan.md` next to this file.

## 1. The proposed floor (2026-11-20: latest Ubuntu, latest Fedora, Arch as the Omarchy build; Wayland only; four desktops)

"Latest" on 2026-11-20, from the distros' own package data (Launchpad API for Ubuntu, mdapi + src.fedoraproject.org for Fedora, archlinux.org JSON + the basecamp/omarchy, omacom-io/omarchy-iso and omacom-io/omarchy-pkgs repositories for Omarchy). **Arch is supported only as the Omarchy build**; plain Arch has no defaults, so nothing below claims one: it runs when the probes of §11 pass and refuses otherwise (§9).

| | **Ubuntu 26.10** (stonking) | **Fedora 45** | **Omarchy v4.5.0** (Arch, Hyprland) |
|---|---|---|---|
| Released | 2026-10-15 [v] | 2026-11-03 [v] | 2026-11-05 (tag v4.5.0; branch `quattro`) [v] |
| Kernel | 7.3 (7.3.0-11.12) [v] | 7.3.5-300.fc45 [v] | **`linux-omarchy` 7.2.15-2** (Arch `linux` PKGBUILD + BORE/ADIOS patches; variants `-bore`, `-eevdf`, `-muqss`, `linux-t2`; `omarchy kernel set` switches) [v]. Arch repos: linux 7.3.5, linux-lts 6.18.64, linux-hardened 7.2.15 [v] |
| systemd | 261.3 [v] | 262-3 [v] | 262.2 [v] |
| xdg-desktop-portal | 1.21.1 [v] | 1.22.1 [v] | 1.22.1; backends `default=hyprland;gtk`, FileChooser `folio;gtk`, Secret `gnome-keyring` [v: `config/xdg-desktop-portal/hyprland-portals.conf`] |
| polkit / agent | 127 / desktop agents [v] | 127 / desktop agents; Sway spin: `lxqt-policykit` (required by sway-config-fedora 0.4.3) [v] | 128 / **the Omarchy shell** (quickshell `Quickshell.Services.Polkit`); no hyprpolkitagent [v: `shell/plugins/polkit/`, base packages] |
| Session bus | dbus-broker 37 (new default) [v] | dbus-broker 37 [v] | dbus (Arch default dbus-broker since 2024) [s] |
| GNOME | 51.0, portal 51.0 [v] | 51.0, portal 51.0 [v] | — |
| KDE Plasma | **6.7.5** (plasma-workspace, kwin, xdg-desktop-portal-kde) [v] | **6.8.1** [v] | — |
| Sway | 1.12-1 (universe) + xdg-desktop-portal-wlr 0.8.4 [v] | 1.12-2.fc45 + xdg-desktop-portal-wlr 0.9.0; Sway Spin = sway-config-fedora 0.4.3 (Waybar, swaylock, swayidle, lxqt-policykit, grimshot) [v] | — |
| Hyprland | 0.56.2+ds-1 (universe) + xdg-desktop-portal-hyprland 1.4.1 [v] | not packaged; no F45 COPR build (solopasha stops at F44 / 0.51.1) [v] | **0.57.2-3** (own build in omarchy-pkgs) + xdg-desktop-portal-hyprland 1.5.0 (Arch) [v]; configured through Omarchy's Lua layer (`o.bind`, `hl.*`), user files in `~/.config/hypr/*.lua` [v] |
| Tray host | GNOME: AppIndicator extension (ubuntu-appindicators) [i]; KDE: Plasma [v] | GNOME: `gnome-shell-extension-appindicator` 66 in repos, not default [v]; KDE: Plasma; Sway spin: Waybar [v] | the Omarchy shell bar (`Quickshell.Services.SystemTray`), no Waybar [v: `shell/plugins/bar/widgets/Tray.qml`, base packages] |
| Clipboard history | none by default | none by default (Klipper on KDE) | Omarchy shell clipboard panel over `wl-paste --watch`; **skips entries typed `x-kde-passwordManagerHint`** or `CLIPBOARD_STATE=sensitive` [v: `shell/plugins/clipboard/capture.sh`] |
| Default browser | Firefox snap [v] | Firefox rpm [s] | **Google Chrome** (`google-chrome` in `omarchy-base.packages`); `omarchy install browser` adds chromium (omarchy-chromium-bin 148), brave, edge, firefox, zen [v] |
| `CONFIG_LSM` | `landlock,lockdown,yama,integrity,apparmor,bpf` [v] | `lockdown,yama,integrity,selinux,bpf,landlock,ipe` [v] | `landlock,lockdown,yama,integrity,bpf` [v: `pkgbuilds/linux-omarchy/config.x86_64`]; linux-lts / linux-hardened: **not checked** (GitLab blocks fetches) → probe |
| BPF LSM / BTF / `SECURITY_PATH` / unpriv BPF | y / y / y / off [v] | y / y / y / off [v] | y / y / y / off [v] |
| fs-verity / built-in signatures | y / y [v] | y / not set [v] | y / y [v] |
| Secure Boot → lockdown | `LOCK_DOWN_IN_SECURE_BOOT=y` → integrity [v] | `LOCK_DOWN_IN_EFI_SECURE_BOOT=y` → integrity [v] | no such option (Arch carries no SB-lockdown patch); `LOCK_DOWN_KERNEL_FORCE_NONE` → **none** [v]. Omarchy installs Limine 12.x as a UKI with Plymouth and never enrols Secure Boot keys (no sbctl anywhere) → SB **off** on a stock install [v] |
| Filesystem / encryption | ext4 [s] / optional LUKS | btrfs (`/`, `/home` subvolumes) [s] / optional LUKS | **btrfs** with snapper + limine-snapper-sync; LUKS chosen in the installer (`encrypted` mode) [v]; subvolume layout not read [i] |
| Yama `ptrace_scope` | 1 [s] | 0 (elfutils-default-yama-scope) [v] | kernel default 1; no override found in Omarchy [s] |
| Login / session manager | GDM / SDDM | GDM / SDDM | SDDM + **UWSM** (`graphical-session.target` exists; `dbus-update-activation-environment --systemd --all` at start) [v: `install/login/sddm.sh`, `omarchy-sleep-lock.service`, `default/hypr/autostart.lua`] |
| Fingerprint | fprintd on request | fprintd on request | optional: `omarchy-setup-security-fingerprint` installs fprintd/libfprint-git [v] |
| Homebrew | works (docs) [v] | works (docs) [v] | not installed; `base-devel`, curl, git present → expected to work [i: verify in the Omarchy VM] |

**Why Ubuntu 26.10 and not 26.04 LTS.** The user asked for the latest release, and 26.10 is it. It also matters technically: 26.04 LTS ships kernel 7.0 with `CONFIG_LSM` lacking `bpf`, Landlock ABI 8, GNOME 50.1, Plasma 6.6.7, Hyprland 0.53.3, Sway 1.11 and dbus-daemon [v]. 26.04.2 (February 2027) brings the HWE 7.3 kernel whose config includes `bpf` [i]. Status for 26.04: "may work, not tested; revisit at 26.04.2".

**Arch.** Only the Omarchy build is supported: its defaults above are the floor for "Arch", and the Omarchy VM is the test target. Everything else on Arch (plain installs, other kernels, other `lsm=` lines, other agents/portals/trays) is unsupported: the app runs if every required chain finds a link and refuses otherwise, naming the missing item and the `pacman` fix (§9). Omarchy's own `omarchy kernel set` and a user-installed `linux-lts` (6.18, Landlock ABI 7) or `linux-hardened` are exactly the cases where the chains must pick weaker links or refuse; the plan tests them in the Omarchy VM.

**Test VMs (the lead's matrix) and what each desktop is tested on**

| VM | Distro / desktop | Answers |
|---|---|---|
| `vm-fedora-gnome` | Fedora 45 Workstation, GNOME 51, UEFI **with Secure Boot** | GNOME paths (portal shortcuts with tokens, Clipboard portal, AppIndicator absent by default), lockdown **integrity** + BPF, btrfs fs-verity, Yama 0 |
| `vm-kubuntu` | Kubuntu 26.10, Plasma 6.7.5; optional `apt install sway` session | KDE paths (no token, `ext-data-control`, Klipper hint), Ubuntu kernel/LSM, ext4 verity feature + `tune2fs`, snap Firefox + proxy, Sway 1.12 with xdp-wlr 0.8.4 and no polkit agent in that session |
| `vm-fedora-sway` | Fedora 45 Sway Spin (sway-config-fedora: Waybar, swaylock/swayidle, lxqt-policykit, SDDM) | Sway on Fedora: Waybar tray, compositor bindings only, portal = wlr + gtk, lxqt-policykit agent present (verify it is autostarted) |
| `vm-omarchy` | Omarchy v4.5.0 (Arch, Hyprland 0.57.2, Omarchy shell, UWSM, Limine UKI, btrfs, LUKS, Secure Boot off) | Hyprland paths (xdph 1.5.0 GlobalShortcuts without token, `ext-data-control`, Omarchy clipboard hint), lockdown none + BPF, Chrome native messaging, Homebrew on Arch, kernel swap to linux-lts / linux-hardened |

Hyprland on Ubuntu 26.10 (0.56.2 from universe) stays supported as "Ubuntu + Hyprland" but has no VM in the matrix; the Omarchy VM is the Hyprland reference, and Fedora Hyprland stays unsupported.

**Untested under this VM set**: GNOME on Ubuntu (the AppIndicator extension on by default, snap Firefox through the proxy) and KDE on Fedora (Plasma 6.8.1 with xdg-desktop-portal-kde 6.8.1). Cheapest cover for the first: a GNOME session on `vm-kubuntu` (`sudo apt install ubuntu-desktop-minimal`, then choose "Ubuntu" at login) [i]; Fedora KDE stays untested unless a fifth VM is added (it would only show 6.8.1-vs-6.7.5 backend differences, open question 18).

Portal backend per desktop (what the app can rely on) [v: backend sources at those versions]:

| Interface | GNOME 51 | KDE 6.7/6.8 | Hyprland (xdph 1.4.1 Ubuntu / 1.5.0 Omarchy) | Sway (xdp-wlr 0.8.4 / 0.9.0) |
|---|---|---|---|---|
| GlobalShortcuts | yes, `Activated` carries `activation_token` | yes, **no token** | yes, **no token** | **no** (compositor keybinding only) |
| RemoteDesktop (+ `ConnectToEIS`) | yes | yes | no | no |
| Clipboard (portal) | yes (`org.gnome.Mutter.Clipboard`) | yes | no | no |
| `ext-data-control-v1` (Wayland) | **no** | yes | yes | yes |
| Background (autostart) | yes | yes | no (xdg-desktop-portal-gtk may answer) | no (gtk) |
| FileChooser / OpenURI | yes | yes | gtk (Omarchy: `folio`) | gtk |
| StatusNotifierWatcher (tray) | only with the AppIndicator extension | yes | Omarchy shell / Waybar | Waybar (Fedora spin) |
| polkit agent in session | GNOME Shell | polkit-kde-agent | Omarchy shell; Ubuntu Hyprland: hyprpolkitagent 0.1.3 if installed [v: universe] | lxqt-policykit (Fedora spin) [v]; Kubuntu Sway session: none unless installed [i] |

Floor per component (what the code may assume; the probes verify every line at run time):

| Component | Floor | Why |
|---|---|---|
| Kernel | **7.2** (Omarchy) — 7.3 on Ubuntu/Fedora | Landlock ABI 10/11 (scopes, audit, TSYNC, RESOLVE_UNIX, UDP; 11 adds the `NO_NEW_PRIVS` flag) [v: syscalls.c]; `SO_PEERPIDFD` (6.5), `PIDFD_GET_INFO` (6.13), `memfd_secret` default-on (6.5), `mseal` (6.10), `PR_SET_MDWE` (6.3) + `NO_INHERIT` (6.6); BPF kfuncs `bpf_get_fsverity_digest` (6.8, LSM only) [v: measure.c], `bpf_get_task_exe_file`/`bpf_path_d_path`/`bpf_get_file_xattr` (6.12) [v]. A linux-lts 6.18 on Omarchy has all of these but Landlock ABI 7 → chain C6 "Reduced". |
| systemd | **261** | `systemd-creds --user` (256), user-manager sandboxing options, `PassPIDFD=` (258) [v: NEWS]. |
| xdg-desktop-portal | **1.21.1** | Registry, GlobalShortcuts v2 with tokens and `ConfigureShortcuts`, RemoteDesktop v2, Clipboard v1; app id mandatory for GlobalShortcuts and `RequestBackground` [v: 1.21.0 notes]. |
| polkit | **127** | pidfd subjects since 124 [v]. |
| GNOME | **51** | token forwarding in the GlobalShortcuts backend, Clipboard backend [v]. |
| KDE Plasma | **6.7** (Ubuntu) / 6.8 (Fedora) | both backends have clipboard, globalshortcuts, remotedesktop, inputcapture [v]. |
| Sway | **1.12** | portal backend is Screenshot + ScreenCast only [v: xdp-wlr README]. |
| Hyprland | **0.56** (Ubuntu) / 0.57 (Omarchy) | xdph 1.4.1: GlobalShortcuts, Screencopy, Screenshot; 1.5.0 adds InputCapture, WorkspaceCapture [v]. |
| Rust toolchain | 1.99.1 | the Docker check used by gaps §1 [v]. |

Landlock on the floor kernels, from `security/landlock/syscalls.c` [v]: 7.2 = ABI 10, 7.3 = ABI 11, 6.18 (linux-lts) = ABI 7. CI (`ubuntu-latest`, kernel 6.8) has ABI 4, so the Landlock code takes "best effort for this ABI" and the probe reports what it got.

Yama: with `PR_SET_DUMPABLE(0)` on every Vaultkeeper process the value is irrelevant for attach; Fedora's 0 still means `/proc/<pid>/exe` and `process_vm_readv` of *dumpable* processes are open to same-uid peers, which is why the ptrace chain (§11, C3) wants the BPF link on Fedora. `linux-hardened` ships its own sysctl defaults and may disable unprivileged user namespaces; none of that is assumed — the probes report it.

## 2. Ideas per gap

Effort: S ≤ 2 days, M ≤ 2 weeks, L > 2 weeks.

### 2.1 Build and CI (gaps §1)

| Gap | Idea | Effort | Recommendation |
|---|---|---|---|
| 3 compile errors, no Linux CI | Add `linux.rs` arms for `dock` (no-op) and `placement` (remember last size; Wayland forbids positioning), make `download_and_stage` `cfg(target_os = "macos")` and give `install_unavailable.rs` the trait surface the daemon expects. CI: `ubuntu-latest` (26.04 image when GitHub ships it, else a `fedora:45` container) running `cargo check --all-targets`, `clippy`, unit tests; build with winit's X11 feature off. | S | Do first; nothing else is testable before. |

### 2.2 Process identity and IPC (gaps §6.1, §6.5, §6.7; §3 browser identity)

**Mechanisms on the floor** [v unless marked]:

- `getsockopt(SO_PEERPIDFD)` on an accepted `AF_UNIX` stream returns a pidfd for the peer's *connect-time* `struct pid` (`sk->sk_peer_pid`), even if the peer already exited (`PIDFD_STALE`) [v: `net/core/sock.c` v7.3]. `SO_PEERCRED` returns the peer's **effective** uid/gid at connect time [v: `cred_to_ucred` uses `cred->euid/egid`].
- `ioctl(pidfd, PIDFD_GET_INFO)` returns `pid`, `tgid`, `ppid`, `ruid/rgid/euid/egid/suid/sgid/fsuid/fsgid`, `cgroupid` (always), optional exit info and coredump mask [v: `include/uapi/linux/pidfd.h` v7.3]. No executable path or inode is exposed.
- `poll(pidfd)` becomes readable when the process exits [v: pidfd_open(2)].
- **`/proc/<pid>/exe` is gated by `ptrace_may_access(PTRACE_MODE_READ_FSCREDS)`**, which for a non-dumpable task requires `CAP_SYS_PTRACE` [v: `fs/proc/base.c` line 1787 under `proc_pid_get_link`; `kernel/ptrace.c` `task_still_dumpable` → `TASK_DUMPABLE_OWNER` or `ptrace_has_cap`]. **Consequence: once the daemon calls `PR_SET_DUMPABLE(0)` (or is setgid, which clears dumpable), no same-uid client can read its `/proc/<pid>/exe`, so the client-side check in `crates/ipc/src/cli_access.rs:212` fails. Likewise the daemon cannot read the exe of a UI/host process that has already hardened itself.** Neither existing doc notes this.
- fs-verity: `FS_IOC_MEASURE_VERITY` returns a constant-time digest; supported on ext4, f2fs, btrfs only [v: kernel docs]. Ubuntu root is ext4, Fedora Workstation btrfs [s]; XFS and overlay are out.
- polkit ≥ 124 accepts a `pidfd` in the `unix-process` subject [v: NEWS; `polkitunixprocess.c` `"pidfd"` property]; dbus-broker ≥ 34 and the D-Bus spec expose `ProcessFD` from `SO_PEERPIDFD` [v].

| Gap | Idea | Effort | Recommendation |
|---|---|---|---|
| §6.1 pid recycled between connect and check | Daemon side: `SO_PEERPIDFD` → `PIDFD_GET_INFO` (uid == own euid, take `pid`) → `openat("/proc/<pid>/exe", O_PATH)` + `fstat` → compare `(st_dev, st_ino)` with `/proc/self/exe` → **then** `poll(pidfd, 0)`: if readable, the peer exited during the check and the pid may have been reused, so reject. Crate: `libc` 0.2.191 lacks `SO_PEERPIDFD`/`PIDFD_GET_INFO`/`pidfd_info` [v: grep], `rustix` 1.1.6 has `pidfd_open/getfd/send_signal` only [v]; define the two constants and the struct locally (`SO_PEERPIDFD = 77`, `PIDFD_GET_INFO = _IOWR(0xFF, 11, struct)`). | S | Do it. Still a mistake guard, not a boundary (design §7.6 stands), except in the setgid build. |
| §6.1/§6.7 client verifies the daemon | Replace "read the daemon's `/proc/<pid>/exe`" (hidden once the daemon is non-dumpable) with checks that survive it, strongest first: (a) the BPF `socket_bind` gate enforcing (shared probe, §12.9): only enrolled builds can bind under `$XDG_RUNTIME_DIR/vaultkeeper/`, so the socket is authentic by construction — the real link; (b) the socket's directory is ours (0700, owner = euid, no symlink, checked on an `O_PATH` fd) and the peer uid from `PIDFD_GET_INFO`/`SO_PEERCRED` equals ours; (c) the peer's cgroup: `/proc/<pid>/cgroup` is world-readable even for a non-dumpable task, `statx` of `/sys/fs/cgroup/<that path>` must equal `PIDFD_GET_INFO.cgroupid` (cgroup2 id = directory inode [s]; binds the name to the pidfd), and the name must be a Vaultkeeper unit or app scope (`io.github.avbel.Vaultkeeper.service`, `app-*io.github.avbel.Vaultkeeper*.{scope,service}`); started outside systemd → recorded as Reduced, not refused; (d) a deb/rpm setgid build could add `SO_PEERCRED.egid` (not planned). A same-uid process can name its own unit anything, so (b)+(c) are mistake guards, (a) is the defence. The daemon's first frame reports its version and exe identity so the client can still say "Vaultkeeper was updated" (gaps §6 item 7). | S | Do it (plan 2c); drop `SameExecutable` for the client→daemon direction on Linux. |
| Hardened clients vs daemon check | Clients (UI, CLI, browser host) connect and complete the identity handshake **before** `PR_SET_DUMPABLE(0)`; the daemon verifies once per connection and binds the identity to the socket (a CLOEXEC socket dies on exec, so "re-check before sensitive ops" of design §7.6 is unnecessary and would fail). The UI must not show vault data before it hardens; order: connect → verified → `PR_SET_DUMPABLE(0)` → request data. | S | Do it; document the ordering in `hardening.rs`. |
| §6.5 any same-uid process can use the socket | Per-request confirmation through polkit `auth_self` with a **pidfd subject** (polkit ≥ 124 [v]); the man page warns `auth_self` is "not restrictive enough for most uses on multi-user systems" [v: polkit(8)] — correct for us: we want exactly "the session owner confirms". Actions: `…reveal`, `…ssh-sign`, `…browser-fill`, each `allow_active=auth_self`, with an optional `auth_self_keep` variant for a "trust for 5 min" setting (polkit keeps it ~5 min [v]). | M | Build with quick unlock; same policy file. |
| §6.7 package upgrade under a running daemon | Three layers: (1) packaging restarts the user unit: Debian `dh_installsystemduser` snippets run `deb-systemd-invoke --user daemon-reload; restart` in **every** logged-in user's manager (it enumerates `/run/user/*/systemd/io.systemd.Manager`) [v: autoscripts; deb-systemd-invoke]; rpm `%systemd_user_postun_with_restart` marks `Markers=+needs-restart` on each `user@` manager and the `%transfiletriggerpostun` on `/usr/lib/systemd/user/` runs `systemctl --user -M <uid>@ enqueue-marked` [v: macros.systemd.in, triggers.systemd.in, systemd-update-helper]; Arch: a pacman hook that loops `systemctl --machine=<uid>@ --user restart vaultkeeper.service` [i]. (2) Daemon self-check: compare `fstat(/proc/self/exe)` with `stat(<install path>)` on each accepted connection; on mismatch finish in-flight work, then `execve(<install path>)` with a `--reexec` flag that re-reads state from the sealed store (the key is gone anyway unless the setgid/FIDO path re-derives it). (3) Clients stop checking the daemon's exe (row above). | S | Do (1) and (3) in v1; (2) is a nicety. |
| Browser identity (gaps §3) | Direct spawn: parent is the browser; read `/proc/<ppid>/exe` **by `PIDFD_GET_INFO.ppid` of self** and match known binaries (`/usr/lib/firefox/firefox`, `/opt/google/chrome/chrome`, `/usr/lib/chromium/chromium`, Brave, Edge). Through the native-messaging proxy (snap/Flatpak Firefox), the parent is `xdg-native-messaging-proxy` and argv is `[path, manifest_path, extension_id]` in Mozilla mode or `[path, origin]` in Chromium mode [v: `xnmp-impl.c` lines 480-485]; identify the browser from the manifest path/origin, record "via proxy" in the pairing UI. Browsers may be dumpable [i]; if not, fall back to "unknown parent". Pairing stays the gate. | S | Do it; it is diagnostics and UI, not security. |
| fs-verity digest as identity | `fsverity enable` in postinst (ext4/btrfs only), compare `FS_IOC_MEASURE_VERITY` digests instead of `(dev, ino)`; survives package upgrades when the digest list is signed. Needs `CAP_SYS_PTRACE`-free access to the peer's exe (same dumpable problem) and a filesystem check. | M | Later, as part of the BPF LSM hardened mode (design §5.6), where the kfunc `bpf_get_fsverity_digest` makes it a kernel-side check. |

### 2.3 Daemon memory and self-sandboxing (gaps §6.2, §3 process hardening, browser "hardened" gate)

| Mechanism | Floor fact | Effort | Recommendation |
|---|---|---|---|
| `PR_SET_DUMPABLE(0)` | Blocks same-uid ptrace, `/proc/<pid>/{mem,maps,environ,fd,exe}`, `process_vm_readv`, `pidfd_getfd` regardless of Yama [v: `ptrace.c`]. Bitwarden does exactly this (`process_isolation/linux.rs`) [v]. | S | Do it in daemon, UI and browser host, after the IPC handshake (2.2). This is the Linux `runtime_hardened()` gate for `browser_status.rs`: "dumpable cleared" ⇔ "other same-uid processes cannot read this process". |
| `umask(077)`, `RLIMIT_CORE=0` | Exists (`RLIMIT_CORE`); add umask. | S | Do it. |
| `memfd_secret` | Enabled by default since 6.5 [v: man page]; pages are out of the kernel direct map, mlocked, hibernation inhibited while any exist [v]. `vendor/secure_memory` has no Linux branch today (grep finds only the mlock comment) [v]. | S | Implement the `memfd_secret` → `mlock` fallback chain the design promised (design §3.3). Note the hibernation inhibition: keep the secret mapping alive only while a key is held, so a locked, keyless daemon does not block suspend-to-disk. |
| `mseal` (6.10) | Seals a mapping against `munmap/mremap/mprotect/madvise(DONTNEED…)` [v: kernel docs]. | S | Seal the `memfd_secret` mapping and the sealed-store buffers after allocation; frees nothing, costs nothing. Do not seal heap memory [v: docs]. |
| `PR_SET_MDWE` (6.3) + `PR_MDWE_NO_INHERIT` (6.6) | Refuses W^X transitions process-wide [v: prctl.h]. Slint's renderer (Skia/FemtoVG, GPU drivers) may JIT or map RWX [i]. | S | Daemon: on. UI: try, log and continue if the renderer breaks. `MemoryDenyWriteExecute=` in the unit does the same for the daemon. |
| Landlock self-sandbox | ABI 8 on the floor: fs + TCP rules, signal and abstract-socket scoping, audit flags, `TSYNC`; ABI 9 (7.1) adds pathname-socket resolution, 10 UDP, 11 the `NO_NEW_PRIVS` flag, 12 capabilities/namespaces (7.4, not yet released) [v]. Crate `landlock` 0.4.7 does best-effort ABI negotiation [v: cargo search]. | M | Daemon ruleset: read+exec `/usr`, `/etc`, `/proc/self`; rw `$XDG_DATA_HOME/vaultkeeper`, `$XDG_CONFIG_HOME/vaultkeeper`, `$XDG_RUNTIME_DIR/vaultkeeper`; TCP connect any port (Vaultwarden runs on arbitrary ports), no TCP bind; **do not handle UDP** (glibc DNS needs UDP 53 and Landlock ≥ 10 would then need an explicit rule). Scope `SIGNAL` and `ABSTRACT_UNIX_SOCKET`? Scoping restricts *our* reach, so only turn on `ABSTRACT_UNIX_SOCKET` (we never need abstract sockets; Wayland and D-Bus are pathname sockets). Apply with `TSYNC` after threads start, or before Tokio starts. Protects against the daemon's own bugs (server JSON, sync), not against other same-uid processes: unchanged from design §5.5. |
| seccomp | Unprivileged seccomp needs `no_new_privs` [v: kernel docs via Landlock text]. systemd's `SystemCallFilter=` in a **user** unit sets NNP before exec, which **breaks the setgid daemon** (setgid is not gained under NNP) [v: execve semantics cited in design §5.5]. | M | Non-setgid build: `SystemCallFilter=@system-service @sandbox`, `SystemCallArchitectures=native` in the unit. Setgid build: install the filter in-process with `seccompiler` 0.5 after the group key half is opened and `PR_SET_NO_NEW_PRIVS` is set by the daemon itself. |
| systemd user unit sandboxing | In the per-user manager, options that need a mount namespace (`ProtectSystem=`, `ProtectHome=`, `PrivateTmp=`, `ProtectProc=`, `ProtectKernel*=`) work only with `PrivateUsers=yes` [v: systemd.exec(5)], i.e. an unprivileged user namespace; Ubuntu restricts unprivileged userns for unconfined binaries through AppArmor [s], so `PrivateUsers=yes` may fail there [i]. Namespace-free options work everywhere: `NoNewPrivileges=`, `SystemCallFilter=`, `SystemCallArchitectures=`, `MemoryDenyWriteExecute=`, `LockPersonality=`, `RestrictRealtime=`, `RestrictNamespaces=`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`, `RestrictSUIDSGID=`, `UMask=0077`, `CapabilityBoundingSet=`. | S | Ship `vaultkeeper.service` (user) with the namespace-free set; try `PrivateUsers=yes` + `ProtectSystem=strict` + `ProtectHome=read-only` + `ReadWritePaths=` behind a drop-in the user can enable after it is verified per distro. No `NoNewPrivileges=`/`SystemCallFilter=` in the setgid variant (see seccomp row). |
| Yama | Irrelevant once dumpable is 0; still, document that Fedora runs `ptrace_scope=0` [v]. | — | Mention in the security notes. |

### 2.4 Secrets at rest and quick unlock (gaps §3 token storage, §3 quick unlock, §6.4; design §5.5 revisited)

**What the floor changes in design §5.5–5.6.** The analysis there stands: no LSM, portal, keyring or TPM policy distinguishes a same-uid process; the setgid daemon is the only kernel-enforced boundary; BPF LSM adds content-based identity. Three facts move:

1. `bpf` is in the default LSM list on Fedora 45, Omarchy (`linux-omarchy`) and **Ubuntu 26.10** (not 26.04) [v]. The "optional hardened mode" of §5.6 is therefore available on three of four floor distros today and on Ubuntu's HWE kernel soon [i].
2. **FIDO2 `hmac-secret`** gives Linux a real analogue of the Secure Enclave: a secret that exists only after hardware-verified user presence/verification, with the token's own PIN lockout. The code is already in the tree: `authenticator` 0.5.0 implements `hmac-secret` for `MakeCredential` (`HmacCreateSecretOrPrf`) and `GetAssertion` (`HmacGetSecretOrPrf`, incl. WebAuthn PRF) [v: crate source].
3. `/dev/tpmrm0` is `0660 root:tss` on every floor distro (upstream `tpm-udev.rules`, Fedora uses it unchanged; Debian/Ubuntu `tpm-udev` package) and systemd grants **no** `uaccess` to TPM nodes (neither `50-udev-default` nor `70-uaccess` mention tpm) [v]. A .deb/.rpm may ship its own `TAG+="uaccess"` rule; `systemd-creds --user` needs no device access at all because the root `systemd-creds.socket` service decrypts [v: NEWS 258].

| Gap | Idea | Effort | Recommendation |
|---|---|---|---|
| Token storage `Unsupported` (gaps §3) | Wire `SealedFileStore` (exists) on Linux with the HKDF-under-user-key sealing of design §5.1. | S | v1, first item after the build fix. |
| 2FA-remember token (gaps §6.4) | Wrap it with `systemd-creds encrypt --user --name=<id>.2fa -` through a `BlobWrapper` (the DPAPI slot). Available on the whole floor (systemd ≥ 256; floor is 259) [v]. Key = TPM2 and/or root-only host key + uid/username + machine-id; decryptable by any same-uid process [v: man page], which is exactly the "machine binding" the token needs and nothing more. Run `systemd-creds` as a subprocess (no library API) or speak Varlink to `io.systemd.Credentials` (the man page says this is how per-user credentials are decrypted) [v]. | S | Do it; fall back to "not stored" when `systemd-creds` is missing (containers, non-systemd). |
| Quick unlock in memory (gaps §3) | polkit `auth_self` as decided (design §3.2), with a **pidfd subject** so the check is bound to the UI process that asked [v: polkit ≥ 124]. Key held in `memfd_secret` + `mseal`. | M | v1. |
| **Persistent quick unlock without the master password** — option A: setgid daemon (design §5.5) | Unchanged mechanism. Floor-specific notes: (a) a setgid process is non-dumpable, so clients must verify it by egid (2.2), not by exe; (b) no `NoNewPrivileges=`/`SystemCallFilter=` in the unit; (c) `systemd-creds --user` can wrap `group_half` additionally for machine binding. Covers: other same-uid processes, backups, `LD_PRELOAD`, pre-exec ptrace. Does not cover: root, kernel, per-request consent (still polkit). | M (1–1.5 w) | Keep as the "no hardware" persistent mode for .deb/.rpm/AUR. |
| Option B: **FIDO2 hmac-secret / PRF** (new) | Enrol: `MakeCredential` on the user's security key with `hmac-secret`, `rk=false`, UV required; store credential id + two random salts. The user key (or `group_half` in the setgid build) is wrapped under `HKDF(hmac_secret_output)`. Unlock after restart: `GetAssertion` with `hmac-secret`, UV (token PIN or on-key fingerprint; PIN lockout is enforced by the token, 8 tries then reset [s: CTAP2 spec]) and user presence → derive → unwrap. Same-uid malware with the files cannot derive the secret without the token; with the token plugged in it still needs a touch and the PIN, and the token's lockout bounds PIN guessing. hidraw access: systemd tags `ID_SECURITY_TOKEN` devices `uaccess` [v: `70-uaccess.rules.in` line 64], so no udev rule or group is needed. UX cost: one touch per unlock after a restart (not after a lock, where the in-memory key serves). | M (1–2 w) | **Recommend as the hardware-backed persistent mode**, independent of setgid and of packaging (works from an AppImage too). Reuse the `envelope::KeyAgreement` abstraction; label "Unlock with security key". |
| Option C: TPM2 sealing with PIN + dictionary-attack lockout | `tss-esapi` is at **8.0.0-alpha.4** (unstable API) [v: cargo search]; needs libtss2 C libs; `/dev/tpmrm0` needs the `tss` group or a shipped `uaccess` udev rule [v]; DA lockout is TPM-global and shared with disk encryption. `systemd-creds` has `--with-key=tpm2` and `--tpm2-pcrs=` but **no PIN option** (no `--tpm2-with-pin` in `systemd-creds.xml` v262) [v], so it binds to the machine, never to a user secret. | L | Later; after A and B. Document that TPM-only sealing adds nothing against same-uid attackers (design §5.3 stands). |
| Option D: BPF LSM hardened mode (design §5.6) | Now viable by default on Fedora 45, Omarchy, Ubuntu 26.10 [v]; detect `bpf` in `/sys/kernel/security/lsm` at runtime. Hooks: `file_open` on the key dir allowed only for the daemon's fs-verity digest, `ptrace_access_check` denied against Vaultkeeper, `task_kill` denied, `unix_stream_connect` gated. Fails open except for our paths. | L (4–6 w) | Optional package `vaultkeeper-hardened` later; Ubuntu 26.04 users get it with the HWE kernel [i]. |
| polkit without an agent (design risk 5) | `CheckAuthorization` with `AllowUserInteraction` and no agent returns "not authorized, no challenge" quickly [i]; probe once at startup with a non-interactive call and show the Sway hint. | S | As designed. |

### 2.5 Portals and Wayland (gaps §3 clipboard/hotkey/auto-type/autostart/open links/file dialogs/lock/network/window focus/app id/tray; §4.1; §4.2)

| Gap | Idea | Effort | Recommendation |
|---|---|---|---|
| App id, `Registry.Register` (gaps §4.1) | Pick `io.github.avbel.Vaultkeeper` (design §7.9). Rules [v: Registry XML]: call `org.freedesktop.host.portal.Registry.Register(app_id, {})` before any other portal call, once per connection, and re-register on `NameOwnerChanged`; the id must match an installed `.desktop` basename. Wayland `app_id`: winit `WindowAttributesExtWayland::with_name(app_id, "")` ("general" is the app id, "instance" is a no-op) [v: winit 0.30.13]; Slint exposes it through `BackendSelector::with_winit_window_attributes_hook` behind the `unstable-winit-030` feature [v: i-slint-backend-selector 1.19.0]. Tray id: `ksni::Tray::id()` must return the same string (Slint hardcodes `"slint-tray"`) [v]. | S | Blocker for everything below; do it right after the build fix. Ship the `.desktop` file in every package. |
| Global hotkey (gaps §3) | GlobalShortcuts v2 via `ashpd` 0.14 (zbus 6) [v: cargo search]: `CreateSession` → `BindShortcuts` → `Activated(session, id, timestamp, {activation_token})`. Token delivery by backend: **GNOME 51 forwards it** [v: xdg-desktop-portal-gnome `globalshortcuts.c`]; **KDE 6.8 does not** (emits `Activated` with no options) [v: `globalshortcuts.cpp` line 218]; **Hyprland does not** (empty map) [v: xdph `GlobalShortcuts.cpp` line 186]. Sway has no GlobalShortcuts backend [v: wlr README] → `bindsym … exec vaultkeeper --search` (exists). `ConfigureShortcuts` (v2) opens the desktop's own rebinding UI [v]. | M | v1 on GNOME/KDE/Hyprland; keep the CLI fallback. |
| Quick Panel focus (gaps §3 window focus; design §6) | GNOME: pass the `activation_token` from `Activated` to the UI process in `XDG_ACTIVATION_TOKEN`; winit reads that variable on window creation [v: winit `startup_notify.rs`]. KDE and Hyprland: the portal emits no token [v: backend sources]; Sway has no portal shortcut at all. Those three rely on new-window focus: Sway and Hyprland focus new toplevels by default [i]; KWin grants focus to a new window at its default focus-stealing level [i]. Fallback for a misbehaving KWin: keep the UI process alive (hidden) and let it call winit `request_activation_token()` before it shows the panel; the compositor honours a token requested by a recently active client [i]. The daemon cannot mint a token without a surface. Chain C10 in §11. | M | Verify on KDE first; it is the only desktop where both routes are uncertain. |
| Clipboard (gaps §3, §4.2) | KDE/Sway/Hyprland: `ext-data-control-v1` via `wl-clipboard-rs` 0.9.5 with `x-kde-passwordManagerHint: secret` (design §7.3). GNOME: no data-control in Mutter 51 [v: gaps §4.2]; the Clipboard portal exists in the GNOME backend (`clipboard.c` → `org.gnome.Mutter.Clipboard.SetSelection`) [v] but only inside a RemoteDesktop session [v: Clipboard XML], which needs `DeviceType::Keyboard\|Pointer`, `persist_mode=2`, a saved `restore_token`, and `RequestClipboard` before `Start` (the order the portal requires) [v: Bitwarden `portal_backend.rs`]. GNOME shows the remote-control indicator while the session is open and the password hint is not supported [v: Bitwarden comment]. Hyprland's portal has no RemoteDesktop/Clipboard [v], so this route is GNOME/KDE only. | M | KDE/Sway/Hyprland via data-control in v1. GNOME: ship the portal route behind a setting ("Allow Vaultkeeper to control the clipboard through the remote-desktop permission"), and otherwise copy from the focused UI window with best-effort clear. Both as Bitwarden does. |
| Auto-type (gaps §3) | GNOME/KDE: RemoteDesktop v2 with `restore_token` + `ConnectToEIS` → libei sender (`reis` crate) for key events; the same session can carry the clipboard. Sway/Hyprland: `zwp_virtual_keyboard_v1` (Hyprland's portal lacks RemoteDesktop) [v]. The "previous app" problem stands (design §7.4). | L (2–3 w) | After v1. One RemoteDesktop session object shared by clipboard and auto-type on GNOME/KDE. |
| Autostart (gaps §3) | `Background.RequestBackground(autostart=true)` requires a valid app id since 1.21.0 [v] → after `Registry.Register`. Sway/Hyprland: `exec`/`exec-once` (design §7.5). The systemd **user unit** is the better Linux answer for the daemon: `vaultkeeper.service` with `WantedBy=graphical-session.target`, enabled by the package (`dh_installsystemduser`, `%systemd_user_post`) [v]; portals/autostart then only cover the tray UI if it is a separate process. | S | Unit for the daemon; portal autostart only when the user turns the tray on under GNOME/KDE. |
| Open links (gaps §3) | `OpenURI.OpenURI` via `ashpd` (works for host apps; no app-id gating) [i]; fallback `xdg-open`. | S | v1. |
| File dialogs (gaps §3) | `rfd` 0.18 with the `xdg-portal` feature → FileChooser portal [v: Cargo.lock has rfd 0.18]. | S | v1. |
| Lock and sleep (gaps §3) | logind `Session.Lock`/`LockedHint`, `Manager.PrepareForSleep`, plus `org.gnome.ScreenSaver`/`org.freedesktop.ScreenSaver` `ActiveChanged` (design §7.2). zbus 5.19 is already a dependency [v]. | S | v1. |
| Network change (gaps §3) | NetworkManager `StateChanged` or the existing probe; `AF_NETLINK` route socket if the unit's `RestrictAddressFamilies=` allows it. | S | Probe only in v1. |
| Tray (gaps §3) | `ksni` 0.3.7 `Tray` trait has `icon_name`, `icon_theme_path`, `icon_pixmap`, `activate`, `watcher_offline` [v: docs.rs]; no xdg-activation token method [v]. GNOME needs the AppIndicator extension: Ubuntu's `gnome-shell-extension-appindicator` v66 declares shell 45–51 [v: metadata.json]; Fedora Workstation does not ship it [s]; the extensions.gnome.org listing carries a "GNOME 51: use the fork" note [s]. Use `ksni` directly with `<appid>-symbolic` + the pixmap fallback, detect `org.kde.StatusNotifierWatcher` (design §4). GNOME 51 release notes add no tray [v]. | S | v1. |

### 2.6 Browser integration (gaps §3 browser gate/manifests/identity; §4.3; design §7.7; risk 6)

Facts [v unless marked]:

- The **WebExtensions portal never landed upstream**: PR flatpak/xdg-desktop-portal#705 was closed 2025-03-25 [v: gh]; xdg-desktop-portal 1.22.1 has no `org.freedesktop.portal.WebExtensions` in `data/` [v]. It was replaced by **`xdg-native-messaging-proxy`** 0.1.0 (2025-03-26), D-Bus name `org.freedesktop.NativeMessagingProxy`, which must be explicitly allowed per sandboxed app because it is "potentially INSECURE" by design [v: README]. Packaged on Ubuntu 26.04 and 26.10 (0.1.0-1), Fedora 45 (0.1.0-4), Debian forky, AUR [v].
- Firefox gained the proxy client in **157** (2026-09-29) [v: `NativeMessaging.sys.mjs` diff 156→157; release date whattrainisitnow]; the pref `widget.use-xdg-desktop-portal.native-messaging-proxy` defaults to **0** (off) and must be set by the snap/Flatpak packaging or policy [v: StaticPrefList]. Whether Ubuntu's Firefox snap and Mozilla's Flatpak set it is **unverified** [i]; a third party reports the Flatpak needs `--talk-name=org.freedesktop.NativeMessagingProxy` by hand and Firefox ≥ 158 [s].
- The proxy reads the **standard host directories**: `~/.mozilla/native-messaging-hosts`, `$XDG_CONFIG_HOME/mozilla/native-messaging-hosts`, `/usr/lib{,64}/mozilla/native-messaging-hosts`; Chromium mode: `$XDG_CONFIG_HOME/{google-chrome,chromium}/NativeMessagingHosts`, `/etc/opt/chrome/native-messaging-hosts`, `/etc/chromium/native-messaging-hosts` [v: `xnmp-impl.c` 580-604]. The manifest `path` must be absolute [v]. The host is spawned by the proxy with `[path, manifest, extension_id]` (Mozilla) or `[path, origin]` (Chromium) [v].
- Chromium/Chrome: no known proxy client ("its only known use is in Firefox") [v: Firefox docs]; the Chromium snap has no native messaging [s: snapcraft forum, 2021]; Google Chrome .deb/.rpm reads `~/.config/google-chrome/NativeMessagingHosts` [v: Chrome docs].
- Flatpak browsers *without* the proxy still read inside their sandbox: `~/.var/app/<id>/…` (Bitwarden's list: `org.mozilla.firefox/.mozilla/native-messaging-hosts`, `com.google.Chrome/config/google-chrome/NativeMessagingHosts`, `org.chromium.Chromium/config/chromium/NativeMessagingHosts`, `com.microsoft.Edge/…`) [v: `desktop_native/core/src/ipc/mod.rs`], but a host binary outside the sandbox cannot be executed from there; Bitwarden copies a small proxy binary, which a Flatpak still cannot run without `flatpak-spawn --host` [i].

| Gap | Idea | Effort | Recommendation |
|---|---|---|---|
| Hardened gate (`has_hardened_runtime()` false) | Linux `runtime_hardened()` = `PR_SET_DUMPABLE(0)` succeeded in this process (checked back with `PR_GET_DUMPABLE`) and `RLIMIT_CORE == 0`. Optionally also "Landlock domain active" (`landlock_restrict_self` returned 0). | S | v1. Same shape as the Windows DACL flag. |
| Manifest directories | Write to `~/.mozilla/native-messaging-hosts`, `~/.config/{google-chrome,chromium,BraveSoftware/Brave-Browser,microsoft-edge}/NativeMessagingHosts`; these also serve snap/Flatpak Firefox through the proxy. Add the `~/.var/app/…` set only for Flatpak Chromium-family browsers (they spawn nothing anyway, so skip unless a wrapper is shipped). | S | v1. |
| Snap/Flatpak Firefox | Rely on the proxy. Detect it (`org.freedesktop.NativeMessagingProxy` activatable on the session bus) and show in Settings: "Sandboxed Firefox needs Firefox 157+ with the native-messaging proxy enabled". | S | v1 detection; test on Ubuntu 26.10 (snap) and Fedora 45 (Flatpak). |
| Browser identity | See 2.2 (parent exe or proxy argv). | S | v1. |
| Passkeys (gaps §3) | Gate on the polkit quick-unlock availability as planned; FIDO2 hmac-secret (2.4 B) is unrelated to passkey UV. | — | With quick unlock. |

### 2.7 Packaging and upgrades (gaps §5, §6.7; design §7.8)

| Item | Idea | Effort | Recommendation |
|---|---|---|---|
| .deb/.rpm/AUR | Ship: binary, `.desktop` (app id), symbolic icon, polkit `.policy`, `vaultkeeper.service` (user), optional setgid variant with `sysusers.d`/`tmpfiles.d`, optional udev rule `KERNEL=="tpmrm[0-9]*", TAG+="uaccess"` for the later TPM mode. Debian: `dh_installsystemduser` (debhelper 13.31) [v]; rpm: `%systemd_user_post`, `%systemd_user_preun`, `%systemd_user_postun_with_restart` [v]; Arch: `.install` + pacman hook. Target repos: a `.deb` for 26.04/26.10, `.rpm` for Fedora 45, AUR `vaultkeeper-bin`. | M | v1. |
| Binary replacement under a running daemon | Covered in 2.2 (packaging restarts the user unit on all distros; clients stop checking the daemon's exe; daemon self-reexec optional). | S | v1. |
| Flatpak | Still a no-go for v1: no setgid, no system polkit policy, no udev rule, host-process identity from inside a sandbox is meaningless, and the native-messaging proxy cannot exec into a sandbox (manifest `path` must be a host binary; a `flatpak run --command=…` wrapper script is the only route) [v: proxy source; i for the wrapper]. Portals would actually fit a Flatpak for shortcuts, clipboard and auto-type, and `--filesystem=xdg-run/vaultkeeper:create` exports the SSH socket. | L | Reconsider after v1 as a reduced tier (no persistent unlock, no polkit, browser via wrapper). |
| AppImage | As in gaps §5 (copy to `~/.local/lib/vaultkeeper/` first run). FIDO2 persistent unlock (2.4 B) works from an AppImage; setgid does not. | M | Later. |

## 3. Modern security features worth adopting, ranked by value

Note (2026-11-20, user decision): BPF LSM moved from item 11 to the **first link of every chain it can serve** (§11, §12). Items 1–3 and 5–7 remain the links below it; FIDO2 (4) is the quick-unlock chain. Ranking otherwise unchanged.

1. **`SO_PEERPIDFD` + `PIDFD_GET_INFO` + post-check `poll(pidfd)`** for every accepted connection (daemon, SSH agent, browser host): closes the pid-reuse race for good; S effort [v].
2. **`PR_SET_DUMPABLE(0)` after the IPC handshake** in daemon, UI and host, plus `umask(077)`; it is also the Linux hardened-runtime gate for browser integration; S [v]. Beware the `/proc/<pid>/exe` side effect (2.2).
3. **`memfd_secret` + `mseal`** for the key and sealed-store buffers: `vendor/secure_memory` already has the Linux links (`src/secure_key/memfd_secret.rs`, `keyctl.rs`, selected in `secure_key/mod.rs:107`, and it type-checks in the Linux Docker build); what is missing is `mseal` on the mapping and surfacing which link was taken; S [v].
4. **FIDO2 `hmac-secret` persistent unlock** with the already-vendored `authenticator` 0.5.0: the only hardware-verified, hardware-rate-limited key-at-rest on Linux that needs no root install; M [v: crate; s: CTAP lockout].
5. **systemd user unit with namespace-free sandboxing** (`SystemCallFilter=@system-service`, `MemoryDenyWriteExecute`, `LockPersonality`, `RestrictAddressFamilies`, `RestrictNamespaces`, `RestrictRealtime`, `UMask=0077`) and `WantedBy=graphical-session.target`; S [v: systemd.exec]. Not with the setgid variant (NNP).
6. **Landlock ABI 8+ self-sandbox** via the `landlock` crate (fs, TCP connect-only, abstract-socket scope, `TSYNC`); M [v].
7. **`systemd-creds --user`** for the 2FA-remember token (machine binding through the root Varlink service, no TPM device access); S [v].
8. **polkit `auth_self` with pidfd subjects** for quick unlock and per-request confirmation (`auth_self_keep` for "trust 5 min"); M [v].
9. **Setgid daemon** persistent mode for packaged installs (unchanged), with egid-based client verification; M [v: existing analysis].
10. **`PR_SET_MDWE`** in the daemon (and tried in the UI); S [v].
11. **BPF LSM hardened mode** where `bpf` is in `/sys/kernel/security/lsm` (Fedora 45, Omarchy, Ubuntu 26.10): content-based identity with `bpf_get_fsverity_digest`, ptrace/kill denial; L [v for availability].
12. **fs-verity digests** as the executable identity inside (11); M; ext4/btrfs only [v].
13. TPM2 PIN sealing through `tss-esapi` with a shipped `uaccess` udev rule; L; wait for `tss-esapi` 8.0 stable [v: alpha].

## 4. What changes in the existing design docs

| Doc | Statement | Correction |
|---|---|---|
| design §2, gaps §7 | Support floor open; GNOME 46/Ubuntu 24.04 fallbacks | Floor = Ubuntu 26.10, Fedora 45, Omarchy (Arch); Wayland only; GNOME, KDE Plasma, Sway, Hyprland (§1) |
| design §5.6 table | "Ubuntu 24.04 and 26.04: no bpf" | 26.04: confirmed no [v]. **26.10: `bpf` is in `CONFIG_LSM`** [v]. Fedora 45 and Debian forky also carry `ipe` [v]. |
| design §7.6, gaps §6.1 | "compare `/proc/<pid>/exe` (st_dev, st_ino) … re-check before sensitive operations" and gaps §6.7 "with (st_dev, st_ino) the daemon would also reject the new clients" | Non-dumpable processes hide `/proc/<pid>/exe` from same-uid readers [v: `ptrace.c`, `base.c`]. Verify clients once at connect, before they harden; verify the daemon by egid (setgid) or socket-dir ownership + cgroup id, never by exe. Re-checks per request are impossible and unnecessary (CLOEXEC socket). |
| design §6 | "Token sources: the GlobalShortcuts `Activated` signal (newer portal versions [i])" | Portal ≥ 1.21.0 carries `activation_token` [v]; **GNOME 51 sends it, KDE 6.8 and Hyprland 0.57 do not** [v]. The focus risk moves from GNOME to KDE. |
| design §7.7, gaps §7 risk 6 | "WebExtensions portal … Ubuntu's Firefox snap has used it since 2022 [s]" | The portal is dead upstream (PR #705 closed) [v]; the replacement is `xdg-native-messaging-proxy`, packaged on all floor distros, with a Firefox ≥ 157 client that is **off by default** [v]. The host's parent is the proxy; argv convention verified. |
| gaps §3 "Browser manifests" | Flatpak dirs under `~/.var/app/` | Proxy-using browsers read the standard host dirs; the `~/.var/app/` set only matters for Flatpak Chromium-family browsers that cannot spawn a host anyway. |
| design §5.3 | TPM "the only Linux mechanism close to Touch ID" | FIDO2 `hmac-secret` is closer (user-verified, hardware-rate-limited, no root install, already implemented in the vendored crate) [v]. TPM stays "later". `systemd-creds` has no PIN option [v]. |
| design §3.3 | `memfd_secret` "then keyctl, then mlock" | `memfd_secret` is on by default since 6.5 [v], so the fallbacks matter only for containers; note the hibernation inhibition. `vendor/secure_memory` has no Linux implementation yet [v]. |
| design §4, gaps §3 tray | "Ubuntu enables [AppIndicator] [i]" | Ubuntu's extension v66 declares GNOME 45–51 [v]; the e.g.o listing warns about GNOME 51 breakage and points to a fork [s]. |
| design §7.4 | Hyprland auto-type via virtual keyboard "[v]" | Confirmed also from the other side: xdph 1.5.0 has no RemoteDesktop/Clipboard portal [v]. |
| design §9 | Effort table | Add: FIDO2 persistent unlock 1–2 w; Landlock + unit hardening 1 w; proxy detection 0.5 w. Remove: GNOME 46 fallback 0.5 w. |

## 5. Open questions only a real machine can answer

1. KDE 6.8: does a Quick Panel spawned from the daemon on a portal shortcut get focus without a token (KWin focus-stealing prevention at the default level)? Hyprland 0.57 and Sway 1.12 the same.
2. Ubuntu 26.10 Firefox snap and Fedora 45 Firefox Flatpak: is `widget.use-xdg-desktop-portal.native-messaging-proxy` set, and does the proxy spawn `/usr/bin/vaultkeeper` from `~/.mozilla/native-messaging-hosts`? What does `PIDFD_GET_INFO.ppid` of the host point at?
3. `PrivateUsers=yes` in a user unit on Ubuntu 26.04/26.10 with the AppArmor userns restriction: does the unit start?
4. Slint 1.19 UI under `PR_SET_MDWE`: do the Skia/FemtoVG renderers and Mesa still work?
5. GNOME 51 Clipboard portal: does `SetSelection` from a RemoteDesktop session with `persist_mode=2` work after a restore without re-prompting, and does the remote-control indicator stay on for the whole session?
6. `authenticator` 0.5.0 on Linux: hidraw via `ID_SECURITY_TOKEN` uaccess on Fedora/Ubuntu without `libfido2`'s udev rules; UV with on-key fingerprint readers.
7. GNOME 51 top-bar colour and AppIndicator v66 rendering of `<appid>-symbolic` on Ubuntu 26.10; Fedora 45 without the extension (the no-host path).
8. cgroup id check: `stat` inode of `…/app.slice/vaultkeeper.service` equals `PIDFD_GET_INFO.cgroupid` on cgroup2 (expected, unverified here).
9. Omarchy `linux-omarchy` 7.2: Landlock ABI reported by `landlock_create_ruleset(VERSION)` is 10 as the source says; Ubuntu 26.04 HWE 7.3 kernel's `CONFIG_LSM`.
10. polkit with no agent (Sway): fail-fast vs hang, and whether `polkit-1` PAM uses `pam_fprintd` on the floor distros once fingerprint login is enabled.
11. Fedora 45 Hyprland: does solopasha/hyprland (or another COPR) gain an F45 chroot, and at which version? Until then Hyprland is tested on Ubuntu 26.10 only.
12. Ubuntu 26.10 default install: is the root ext4 created without the `verity` feature (expected), and does `tune2fs -O verity` on the mounted root take effect without a reboot?
13. Fedora 45 btrfs: `FS_IOC_ENABLE_VERITY` on a file under `/home/linuxbrew/.linuxbrew/Cellar/...` succeeds as root? And on the KDE spin's layout?
14. BPF LSM under Secure Boot (lockdown integrity) on Fedora, and under lockdown none on Omarchy: programs with `bpf_get_fsverity_digest`, `bpf_path_d_path`, task storage and sleepable `file_open` load and attach? Confidentiality mode (manual `lockdown=confidentiality`) too?
15. Does `openat()` latency with the `file_open` program stay under 2 µs for files of other users and other paths?
16. Sway and Hyprland: does `systemd --user` have `WAYLAND_DISPLAY` on a stock config (for the user-unit autostart link), and does `exec vaultkeeper --search` from a keybinding carry `XDG_ACTIVATION_TOKEN`?
17. Portal `Registry.Register` on xdg-desktop-portal 1.21.1 (Ubuntu): is a `.desktop` file in `$XDG_DATA_HOME/applications` enough for the frontend to accept the app id and show the app name in the GlobalShortcuts dialog?
18. KDE 6.7.5 on Kubuntu 26.10 vs 6.8.1 on Fedora: any difference in the GlobalShortcuts backend or clipboard portal behaviour?

Which VM answers which question (the lead's matrix; §1 VM table):

| Question | VM |
|---|---|
| 1 KDE focus without token; Hyprland/Sway focus | `vm-kubuntu` (KDE, Sway session), `vm-omarchy` (Hyprland), `vm-fedora-sway` |
| 2 Firefox snap / Flatpak and the proxy | `vm-kubuntu` (snap), `vm-fedora-gnome` (Flatpak optional) |
| 3 `PrivateUsers=yes` under AppArmor userns restriction | `vm-kubuntu` |
| 4–10 (portal, SNI, tokens, FIDO2, ssh-agent, systemd-creds, TPM) | all four; TPM: whichever VM exposes a vTPM |
| 11 Hyprland on Fedora 45 | none (Fedora ships none; recheck COPR periodically) |
| 12 ext4 `verity` feature and `tune2fs` on the mounted root | `vm-kubuntu` |
| 13 btrfs `FS_IOC_ENABLE_VERITY` under the Homebrew prefix | `vm-fedora-gnome`, `vm-omarchy` (also under LUKS) |
| 14 BPF LSM under lockdown integrity / confidentiality | `vm-fedora-gnome` (SB on; `lockdown=confidentiality` by hand), `vm-omarchy` (none) |
| 15 `openat` latency with the `file_open` program | `vm-fedora-gnome`, `vm-omarchy` |
| 16 `systemd --user` environment and activation tokens on Sway/Hyprland | `vm-fedora-sway`, `vm-kubuntu` (Sway), `vm-omarchy` (UWSM) |
| 17 `Registry.Register` with a user `.desktop` on portal 1.21.1 | `vm-kubuntu` |
| 18 KDE 6.7.5 vs 6.8.1 backend differences | `vm-kubuntu` vs a Fedora KDE install (not in the matrix; optional) |
| 19 (new) Omarchy: LUKS default, btrfs subvolume layout, `/opt/google/chrome/chrome` path, Omarchy shell polkit agent answering our `CheckAuthorization`, Homebrew install, `omarchy kernel set linux-lts` → which chains degrade | `vm-omarchy` |
| 20 (new) Fedora Sway Spin: is lxqt-policykit autostarted by sway-config-fedora; Waybar `tray` module on; mako present | `vm-fedora-sway` |
| 21 (new) Kubuntu optional Sway session: polkit agent absent → BPF enrol prompt impossible; our Settings text | `vm-kubuntu` |

## 6. Decisions applied (2026-11-20, user) and where they land

| Decision (gaps "Decisions") | Where |
|---|---|
| Latest Ubuntu + latest Fedora, Wayland only, GNOME / KDE Plasma / Sway / Hyprland at the versions they ship | §1 floor and desktop tables; every chain probe in §11 covers only these |
| Homebrew first through `avbel/homebrew-tap`; deb/rpm next; no AppImage | §7; plan phases 6 and 8 |
| "Update automatically" and "Check for Updates…" off and hidden under a package manager | §8 |
| Protections as fallback chains, strongest first, stacking where possible | §11 |
| BPF LSM now, as the first link of file access, ptrace/memory, signals and socket connects; identity by a signed fs-verity digest; one-time privileged install | §12; chains C1, C3, C4, C5 |
| Refuse to start when a required chain has no working link unless `--skip-security-issues` | §9 |
| Hotkeys and shortcut labels as on Windows | §10 |
| Arch is back, but only as the Omarchy build; plain Arch runs only when the probes pass; no Arch default is assumed anywhere; a user-facing requirements list documents what the probes need | §1 (Omarchy column, VM matrix), §9.1, §11 intro |
| Four test VMs: Fedora GNOME (UEFI + Secure Boot), Kubuntu (+ optional Sway), Fedora Sway Spin, Omarchy; every manual check and open question names its VM | §1 VM table, §5 mapping, plan appendix |

## 7. Distribution through the Homebrew tap (requirement A)

Facts about the tap and about Homebrew on Linux, all [v] unless marked:

- `Formula/yrem.rb`: `on_macos { on_arm { url …aarch64-apple-darwin.tar.gz } }`, `on_linux { on_intel { url …x86_64-unknown-linux-musl.tar.gz; sha256 } on_arm { …aarch64-unknown-linux-musl… } }`, `bin.install "yrem"`, `test do assert_match version…"--version"`. The tap has `Formula/` only, no `Casks/` [gh api].
- Prefix `/home/linuxbrew/.linuxbrew`, owned by the managing user [docs.brew.sh/Homebrew-on-Linux]. `Cellar/vaultkeeper/<version>/` changes on every upgrade; `opt/vaultkeeper` is the stable symlink; `brew upgrade` deletes the old version automatically [FAQ].
- A formula's `service do` block is rendered into `~/.config/systemd/user/homebrew.<formula>.service` with only `Type`, `ExecStart`, `Restart`, `RestartSec`, `WorkingDirectory`, `Environment`, `StandardOutput/Error`; the `[Install]` target is `default.target`; nothing in `upgrade.rb` or `formula_installer.rb` restarts a running service, `brew services restart` is manual [brew sources: `service.rb` `to_systemd_unit`, `services/system.rb`, `formula_installer.rb` `install_service`].
- Homebrew formulas install only into the prefix; writing `~/.local/share/applications` or `~/.config` from `install`/`post_install` is not done by formulas (caveats tell the user instead) [Formula Cookbook].

### 7.1 User-writable prefix

Anything with the user's uid can replace `Cellar/vaultkeeper/*/bin/vaultkeeper` and the `opt` symlink. Consequences:

- Path-based identity (`SameExecutable` comparing `/proc/<pid>/exe` strings) is worthless twice over: the path changes on every upgrade, and the file behind it is attacker-writable. Identity has to be the **content**: the fs-verity digest of the ELF enrolled by root (§12). A replaced binary has no verity data, or a digest nobody enrolled, so the BPF link denies it the key file, the daemon sockets and ptrace.
- Without the BPF link installed, Homebrew gives the same guarantee as any user-installed program: a same-uid process can do everything the user can. That is the honest tier statement for Settings ("Standard protection: process isolation relies on the BPF helper; not installed").
- The desktop file and the autostart entry must point at `opt/vaultkeeper/bin/vaultkeeper`, never at a Cellar path.

### 7.2 Quick unlock without root

No polkit policy file, no setgid, no tmpfiles are possible from a formula. What still works:

1. **FIDO2 `hmac-secret`** (chain C7 link 1): the key-encryption key is derived by the authenticator; needs only the `uaccess` udev rules both distros ship for hidraw/FIDO devices [v: systemd `70-uaccess.rules.in`]; `authenticator` 0.5.0 is already vendored.
2. **Presence check without a key at rest**: the daemon keeps the user key in `memfd_secret` and asks fprintd over D-Bus (`net.reactivated.Fprint.Device.VerifyStart`) to confirm a fingerprint; fprintd authorises the caller through its own polkit action, which is allowed for the active session [s]. This is the "polkit → PAM" idea of design §3.2 without a policy file, but it protects nothing at rest: it only gates the *UI*. Label it "Fingerprint unlock (key stays in memory)".
3. A polkit action of our own (`auth_self` with the system dialog and PIN/password fallback) arrives with the one-time root install of the BPF helper (§12.5), which drops `/usr/share/polkit-1/actions/io.github.avbel.vaultkeeper.policy` at the same time.

### 7.3 The app writes its own `.desktop` file

On first start and whenever the rendered content differs, the daemon writes `$XDG_DATA_HOME/applications/io.github.avbel.Vaultkeeper.desktop` (`Exec=/home/linuxbrew/.linuxbrew/opt/vaultkeeper/bin/vaultkeeper`, `TryExec`, `Icon=io.github.avbel.Vaultkeeper`, `Terminal=false`, `Type=Application`, `Categories=Utility;Security;`, `Actions=Search;Generator;` with `vaultkeeper --search` / `--generator`, `X-GNOME-UsesNotifications=true`, `SingleMainWindow=true`), the icons under `$XDG_DATA_HOME/icons/hicolor/{scalable/apps,symbolic/apps}/io.github.avbel.Vaultkeeper{,-symbolic}.svg`, and runs `update-desktop-database` when present. The portal frontend resolves the app id to this file for names and permissions, and `Registry.Register` must use the same id [v: Registry.xml]. The Exec path is the `opt` path for Homebrew and the realpath otherwise (§8 install kind). The writer is portable and unit-tested (template → string).

### 7.4 `service do` and `brew services`: not for the tray daemon

The generated unit would start at `default.target`, before the compositor exists, with no `WAYLAND_DISPLAY`/`DBUS_SESSION_BUS_ADDRESS` (GNOME and KDE import them into `systemd --user` at login; Sway and Hyprland only when the config runs `dbus-update-activation-environment --systemd …` or uwsm [s]); the tray and the UI would fail and `Restart=` would loop. Verdict: **no `service do` block**. "Start at login" is chain C11 (§11): Background portal → the app's own user unit bound to `graphical-session.target` → XDG autostart file → printed instructions. The formula's caveats say so in one line.

### 7.5 `brew upgrade` under a running daemon

Sequence: new `Cellar/<v+1>/bin/vaultkeeper` appears; `opt` is repointed; the old Cellar directory is deleted while the daemon is still running from it (its `/proc/self/exe` now reads `… (deleted)`; the inode lives on). Today's `SameExecutable` (path compare, `crates/ipc/src/peer.rs:150`, built once in `cli_access.rs:84`) then rejects the new CLI with a confusing error. Plan:

- Identity by **file identity, not path**: compare `statx` (`stx_dev`, `stx_ino`, and `stx_mnt_id`) of `/proc/<pid>/exe` with our own, or the fs-verity digest when present (2c). The BPF connect gate (C5 link 1) makes the comparison a mistake guard, as on Windows.
- Detect "updated": at each updater tick and on every CLI connect, `realpath(opt/vaultkeeper/bin/vaultkeeper) != our exe` or our exe link ends in ` (deleted)` → state `Updated`. Tray item "Restart to finish the update", CLI message "Vaultkeeper was updated; it restarts when the vault is locked, or run `vaultkeeper --quit` and start it again". The daemon re-executes the `opt` path with `--tray` when `quiet_for_update()` holds (same gate as the macOS swap).
- With BPF: the new binary is **not enrolled** until the helper enables fs-verity on it and records its digest (§12.4), so the restarted daemon's first probe says "this build is not enrolled → Enroll…"; the enrolment call goes to the root helper over the system bus with a polkit prompt. The old digest stays enrolled until the file is gone.
- Homebrew cannot run `vaultkeeper --quit` before an upgrade (no pre-upgrade hook), and must not: the daemon handles it.

### 7.6 glibc, not musl

yrem is a CLI, so musl-static was free. Vaultkeeper's UI needs `libwayland-client`, `libxkbcommon`, `libEGL`/GLES (Slint's femtovg/skia renderers dlopen the GPU stack at run time), fontconfig/freetype for font discovery, and `libudev` for `authenticator` [i: crate dependency chains; verify with `ldd` on the Docker build]. A static musl binary cannot dlopen the distro's glibc-linked Mesa. Decision: **`x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`, dynamically linked against the system libraries**, built on `ubuntu-latest` (24.04, glibc 2.39) and `ubuntu-24.04-arm`, which is older than either target's glibc [i]. The formula declares no Homebrew dependencies (mixing brew's Mesa with the system compositor is a known failure mode) and lists the apt/dnf runtime packages in `caveats` (`libxkbcommon0 libwayland-client0 libegl1 libfontconfig1 libudev1`; Fedora `libxkbcommon libwayland-client mesa-libEGL fontconfig systemd-libs`). The root helper (§12.7) is the exception: static, musl, no dlopen, because it runs as root from `/usr/local/libexec`.

### 7.7 CI: Linux release artifacts and the formula bump

- `release.yml` job `linux-build`, matrix `{x86_64: ubuntu-latest, aarch64: ubuntu-24.04-arm}`: apt deps, `cargo build --release --locked -p vaultkeeper -p vaultkeeper-bpf`, `strip`, `fsverity digest --compact vaultkeeper` (fsverity-utils from apt) signed with minisign under the existing `UPDATE_SIGNING_KEY` → `vaultkeeper.verity.minisig`; tarball `vaultkeeper-v<ver>-<triple>.tar.gz` = `bin/vaultkeeper`, `libexec/vaultkeeper-bpf`, `share/vaultkeeper/{io.github.avbel.Vaultkeeper.desktop.in, icons/, vaultkeeper.verity.minisig, bpf/}`, `LICENSE`; `.minisig` of the tarball too; both into `SHA256SUMS` in the existing `release` job.
- Job `homebrew` (environment `homebrew`, after `release`, only on a tag): checks out `avbel/homebrew-tap` with a fine-grained PAT (`HOMEBREW_TAP_TOKEN`, contents: write on that repo only), rewrites `version` and both `sha256` lines of `Formula/vaultkeeper.rb` from `SHA256SUMS`, commits `vaultkeeper <ver>` as the workflow's bot identity and pushes. No `brew bump-formula-pr` (that targets PRs); a 20-line Ruby/sed template rewrite is enough and testable (`ruby -c`).
- Formula skeleton: `class Vaultkeeper < Formula`, `desc`, `homepage`, `version`, `license "GPL-3.0-only"`, `on_linux { on_intel {…gnu…} on_arm {…gnu…} }` (no `on_macos`: macOS stays the dmg; a cask can come later), `def install; bin.install "bin/vaultkeeper"; libexec.install "libexec/vaultkeeper-bpf"; (share/"vaultkeeper").install Dir["share/vaultkeeper/*"]; end`, `def caveats` (first run writes the desktop entry; BPF protection: `sudo #{opt_libexec}/vaultkeeper-bpf install`; runtime packages), `test do assert_match version.to_s, shell_output("#{bin}/vaultkeeper --version")`.

## 8. Auto-update under a package manager (requirement B)

Today: `auto_update: bool` (`app/src/settings.rs:184`), the loop in `app/src/daemon/update/mod.rs:203-213` checks GitHub when `auto` or when `check_requested` was set by the tray's "Check for Updates…", and `install_unavailable.rs` already refuses to install on Linux [v].

**Detection** — `vk_platform::install_kind::detect() -> InstallKind { Direct, Homebrew, Deb, Rpm, Cask }`, computed once from `realpath(/proc/self/exe)` (macOS: the bundle path), portable logic over injected inputs so it is unit-tested on macOS:

1. **Marker file next to the binary** (primary, uniform): `<bindir>/../share/vaultkeeper/install-kind` containing `homebrew`, `deb` or `rpm`. The formula ships it inside the tarball's `share/vaultkeeper/` (so it lands in the Cellar), the deb/rpm install it under `/usr/share/vaultkeeper/`. Absent → `Direct` (hand-unpacked tarball or a dev build).
2. **Homebrew path shape** (belt and braces): the realpath contains `/Cellar/vaultkeeper/` and `<prefix>/bin/brew` exists.
3. **dpkg**: `/var/lib/dpkg/info/vaultkeeper.list` exists and names the realpath (no `dpkg -S` spawn).
4. **rpm**: realpath under `/usr/` and `/usr/lib/sysimage/rpm/` or `/var/lib/rpm/` exists → spawn `rpm -qf <realpath>` once (≈50 ms) only if 1 is missing.
5. **macOS cask** (later): `/opt/homebrew/Caskroom/vaultkeeper/` exists → `Cask`; the toggle stays visible but defaults off with the hint `brew upgrade --cask vaultkeeper`.

**Behaviour when managed** (`InstallKind::manager() -> Option<&'static str>` = "Homebrew", "apt", "dnf"):

- Settings loading clamps `auto_update = false` in memory and never writes it back; `Updater::spawn` sets `Status::Managed(manager)` and returns without a task, so no GitHub request ever happens; `check_requested`/`install_requested` are ignored.
- Tray: "Check for Updates…" is not added; the status line reads "Updates: Homebrew".
- Settings (`app/ui/settings.slint:258`): the `Toggle` is replaced by a `SettingRow` "Updates" with description "Managed by Homebrew — run `brew upgrade vaultkeeper`" (`apt`/`dnf` variants), no control. `vaultkeeper --version` prints `install: homebrew`.
- `Direct` installs keep today's behaviour: the toggle, daily checks, and "updates are not installed on this platform yet" (the tarball user gets the release page link).

## 9. Mandatory security baseline (requirement C)

The baseline is the **evaluation of the chains in §11**: a chain is `Required::Refuse`, `Required::Warn` or `Status`. At startup each process (daemon, UI, CLI, browser host) probes the chains relevant to its role; a `Refuse` chain with **no working link** stops the process unless `--skip-security-issues` was given or the issue set was accepted (below). A working link weaker than the chain's **minimum** is a warning (badge in Settings, log line), never a refusal.

| Check | Class | Probe | Minimum | Below minimum |
|---|---|---|---|---|
| Kernel features | Refuse | `uname -r` ≥ 6.5 and `SO_PEERPIDFD` works on a `socketpair` | ≥ 6.13 (`PIDFD_GET_INFO`) | warn |
| Wayland session (daemon, UI) | Refuse | `WAYLAND_DISPLAY` set and the socket connects; `XDG_SESSION_TYPE` is `wayland` or unset | — | — |
| `XDG_RUNTIME_DIR` | Refuse | set, directory, owner = euid, mode 0700, `statfs` says tmpfs | — | — |
| Data dir and secret files | Refuse | owner = euid, not a symlink, dir 0700, files 0600 (modes are repaired, owner/symlink refuse) | — | — |
| Key in memory (C2) | Refuse | `memfd_secret`, then keyctl, then `mlock` | `memfd_secret` | warn ("CONFIG_SECRETMEM off or `secretmem.enable=0`") |
| Anti memory read (C3) | Refuse | `PR_SET_DUMPABLE(0)` succeeds | dumpable(0) **and** (BPF ptrace gate **or** Yama ≥ 1) | warn (Fedora without BPF: "other programs of your account can read Vaultkeeper's memory until BPF protection is installed or `kernel.yama.ptrace_scope=1`") |
| Peer identity (C5) | Refuse | `SO_PEERCRED` | `SO_PEERPIDFD` + `PIDFD_GET_INFO` | warn |
| Self-sandbox (C6) | Warn | Landlock ABI via `LANDLOCK_CREATE_RULESET_VERSION`; `PR_SET_MDWE` | ABI ≥ 8 and MDWE | warn ("Landlock disabled by `lsm=`") |
| BPF protection (C1/C3/C4/C5 link 1) | Warn | `/sys/kernel/security/lsm` contains `bpf`; pinned status map; own digest enrolled; canary denied | installed and enrolled | warn with the Install/Enroll action |
| Portal, notifications, tray watcher, logind | Status | `NameHasOwner` on the session/system bus (2 s timeout) | — | status rows only |
| Secret files at rest (C1) | Refuse | sealed store writable, `write_private_atomic` works | — | — |

Probing is syscalls plus four D-Bus name checks; budget 50 ms, D-Bus asynchronous and cached; Settings has "Re-check".

**The flag and how it travels.** `--skip-security-issues` is parsed in `app/src/cli.rs` for every role. The daemon appends it to the UI child's argv; `--tray` autostart entries, the user unit and the desktop file **never** contain it. For autostart the user accepts a concrete issue set once: `vaultkeeper security accept` (or the dialog's "Start anyway and remember") stores `security.accepted = { fingerprint, issues: [ids] }` in `settings.json`; a start whose refusal set is a subset of the accepted one proceeds with the warning badge; any new issue refuses again. Environment variables are not honoured (ambient, inheritable by accident).

**What the user sees on refusal.** CLI with a tty: a table (check, what failed, how to fix) and exit status 78 (`EX_CONFIG`), plus the two commands (`--skip-security-issues`, `security accept`). Daemon without a tty (desktop launch, autostart): it spawns `vaultkeeper --ui --refusal <report path>` so a real window shows the same table with "Quit" and "Start anyway (not recommended)" (which re-launches the daemon with the flag), and additionally posts an `org.freedesktop.Notifications` notification (works on all four desktops when a notification daemon runs); if even the UI cannot start (no Wayland) the report goes to `$XDG_STATE_HOME/vaultkeeper/last-refusal.txt` and the log. `vaultkeeper security status` prints the full chain table at any time, with the active link and the strength of each chain. Every refusal and warning names the exact missing item and the fix for the detected distribution (§9.1): the same probe failure reads `apt install …` on Ubuntu, `dnf install …` on Fedora and `pacman -S …` / `omarchy …` on Omarchy. No distribution default is assumed: the probes are the only source of truth, which is what makes a non-Omarchy Arch install "unsupported but runnable".

### 9.1 Linux requirements: what the probes need, and the fix per distribution

This list documents the probes of §11; on Ubuntu and Fedora the stock install satisfies every "Refuse" line, on Omarchy too, and on any other Arch setup it is the user's own checklist (support stays "runs if the probes pass"). The app prints the same table with `vaultkeeper security requirements` and the refusal window shows only the failing lines with the fix for the detected distribution (`/etc/os-release` `ID`; `omarchy` or `omarchy-dev` in `pacman -Q` marks Omarchy).

| Item | Probe | Class | Missing → | Fix: Ubuntu 26.10 | Fedora 45 | Omarchy (Arch) |
|---|---|---|---|---|---|---|
| Kernel ≥ 6.5 with `SO_PEERPIDFD`; ≥ 6.13 for `PIDFD_GET_INFO` | `uname -r`, `getsockopt` on a socketpair | Refuse / warn below 6.13 | peer identity chain C5 off | stock kernel | stock kernel | `linux-omarchy` or `linux`; `linux-lts` 6.18 is fine; older custom kernels refuse |
| `CONFIG_SECRETMEM`, `secretmem.enable` not 0 | `memfd_secret()` | Refuse below `mlock` only; warn without memfd_secret | key-in-memory chain C2 reduced | stock | stock | stock; custom kernel: enable `CONFIG_SECRETMEM` |
| `landlock` in the active LSM list, ABI ≥ 8 | `landlock_create_ruleset(VERSION)` | Warn | self-sandbox C6 off/reduced | stock | stock | stock; otherwise add `landlock` to `lsm=` in `/etc/default/limine` `KERNEL_CMDLINE` and run `omarchy-refresh-limine` [i: file names per Omarchy's limine-entry-tool drop-ins] |
| `bpf` in the active LSM list + BTF | `/sys/kernel/security/lsm` | Warn (BPF links unavailable) | C1/C3/C4/C5 fall to their next links | stock (26.04: `lsm=…,bpf` + reboot) | stock | stock; custom kernel: `CONFIG_BPF_LSM`, add `bpf` to `lsm=` |
| BPF helper installed and this build enrolled | pinned status map, own digest, canary | Warn | same | `sudo vaultkeeper security install` | same | same (fsverity on btrfs works; Secure Boot irrelevant) |
| fs-verity on the filesystem holding the binary | `FS_IOC_ENABLE_VERITY` dry run by the helper | Warn (enrol impossible) | BPF identity unavailable | ext4: `sudo tune2fs -O verity <root dev>` + reboot | btrfs: nothing | btrfs: nothing |
| Yama `ptrace_scope ≥ 1` **or** BPF ptrace gate | `/proc/sys/kernel/yama/ptrace_scope` | Warn | C3 reduced | stock (1) | `sudo sysctl kernel.yama.ptrace_scope=1` or install BPF | stock (1) |
| Wayland session | `WAYLAND_DISPLAY` + connect | Refuse (daemon/UI) | app will not start | log in to "Ubuntu" (Wayland) | stock | stock (Hyprland) |
| `XDG_RUNTIME_DIR` on tmpfs, 0700, owned | `statx`/`statfs` | Refuse | app will not start | logind provides it | same | same (UWSM/logind) |
| Data dir owner/mode | `statx` | Refuse (owner/symlink) / repair (mode) | app will not start | `chown -R $USER ~/.local/share/vaultkeeper; chmod 700` | same | same |
| systemd user manager | `$XDG_RUNTIME_DIR/systemd/notify` | Status | unit-based autostart (C11 link 2) unavailable | stock | stock | stock (UWSM) |
| Portal frontend + a backend with GlobalShortcuts | `org.freedesktop.portal.Desktop`; `ListShortcuts` | Status | hotkey C9 → compositor binding | `xdg-desktop-portal-gnome`/`-kde`/`-hyprland` | same (`dnf`) | `xdg-desktop-portal-hyprland` (stock) |
| Clipboard: `ext-data-control-v1` or RemoteDesktop+Clipboard portal | Wayland globals; portal interfaces | Status | C8 → plain clipboard (warn) | GNOME: portal (stock); KDE: stock | same | stock (Hyprland) |
| StatusNotifierWatcher | `org.kde.StatusNotifierWatcher` | Status | no tray (C13) | GNOME: ubuntu-appindicators (stock) | GNOME: `dnf install gnome-shell-extension-appindicator`; Sway spin: Waybar `tray` module | Omarchy shell (stock) |
| polkit agent in the session | `org.freedesktop.PolicyKit1.AuthenticationAgent` registered for the session (`pkcheck`-style probe via `CheckAuthorization` with interaction) | Status | BPF enrol prompt and polkit quick unlock cannot ask | GNOME/KDE: stock; Sway: `apt install polkit-kde-agent-1` or `lxpolkit` and `exec` it | Sway spin: lxqt-policykit (stock) | Omarchy shell (stock) |
| Notification daemon | `org.freedesktop.Notifications` | Status | refusals only in the window/log | stock | stock (Sway spin: mako) | Omarchy shell |
| logind | system bus `org.freedesktop.login1` | Status | lock/sleep events reduced to idle timeout | stock | stock | stock |
| fprintd / FIDO2 device (`uaccess`) | `net.reactivated.Fprint`; hidraw with `uaccess` | Status | quick-unlock links | `apt install fprintd` | `dnf install fprintd` | `omarchy setup security fingerprint` |
| `xdg-native-messaging-proxy` (confined Firefox) | `/usr/libexec/xdg-native-messaging-proxy` | Status | snap/Flatpak Firefox integration | stock (26.10) | `dnf install xdg-native-messaging-proxy` | AUR, only for Flatpak Firefox |

Refusal text format (CLI, window, log): `<item>: <what the probe saw> — <fix for this distribution>`, e.g. `Runtime directory: XDG_RUNTIME_DIR is not set — log in through a session manager (logind) or export XDG_RUNTIME_DIR=/run/user/$(id -u)`; `BPF protection: lsm list "landlock,lockdown,yama,integrity" lacks bpf — Omarchy: add bpf to KERNEL_CMDLINE lsm= in /etc/default/limine, run omarchy-refresh-limine, reboot` (warning, not refusal).

## 10. Hotkeys and shortcuts as on Windows (requirement D)

Defaults and rule: the Quick Panel is **Ctrl+Shift+Space** on Linux (Super+ chords belong to GNOME/KDE, Ctrl+Alt is AltGr on many layouts; same reasoning as Windows), the generator keeps its Windows default too; labels are Ctrl-based; macOS becomes the odd one out. Sites, from `grep cfg!(windows)` [v]:

| Site | Today | Change |
|---|---|---|
| `app/src/settings.rs:371-375` `DEFAULT_HOTKEY` | `cfg(windows)` Ctrl+Shift+Space, `cfg(not(windows))` Cmd+Shift+Space | `cfg(target_os = "macos")` Cmd…, `cfg(not(target_os = "macos"))` Ctrl… |
| `settings.rs:441` `hotkey_display` | `if cfg!(windows) { names } else { symbols }` | `if cfg!(target_os = "macos") { symbols } else { names }` |
| `app/src/hotkey_recorder.rs:20-26` `MODIFIER_HINT`, `UNAVAILABLE_NOTICE` | two-way | three-way: Linux "Ctrl, Alt or Super"; "…reserved by your desktop. Pick another one." |
| `app/src/app/settings_hotkeys.rs:55` AltGr warning | `cfg!(windows) && ctrl_alt_only` | `cfg!(not(target_os = "macos"))` |
| `settings_hotkeys.rs:82` `slint_mods` | Windows: `(meta, control)` | Linux reports Ctrl as `control`, Super as `meta` like Windows → `if cfg!(target_os = "macos") { (control, meta) } else { (meta, control) }`; test at :301 the same |
| Tests pinning strings: `app/tests/hotkey_recorder.rs`, `generator_settings.rs`, `shortcut_hints.rs`, `shortcut_labels.rs` | macOS/Windows expectations | expectations keyed on `target_os = "macos"` vs the rest |
| Other `cfg!(windows)` texts to make three-way (not hotkeys): `app/src/app/reprompt.rs:26`, `security_key.rs:18,248` ("PC"/"Mac" → "computer"), `settings_ctl.rs:21,146,367`, `os/biometrics.rs:18-35` ("Touch ID"/"Windows Hello" → "Fingerprint" or "Security key"), `daemon/tray.rs:148` (Auto icon from the Settings portal `color-scheme`), `app/quick.rs:157` (focus hack around the system prompt; probably needed for the polkit dialog too [i]) | | Windows-only features (`capture_exclusion` :94, Firefox manifest argv shape `cli.rs:25,261`, update asset names) keep `cfg!(windows)` |

**Mapping to the GlobalShortcuts portal.** `BindShortcuts` takes per shortcut an id, a `description` and a `preferred_trigger` in the shortcuts-spec syntax [v: GlobalShortcuts.xml]. Portable conversion, unit-tested: accelerator → trigger: `Ctrl`→`CTRL`, `Shift`→`SHIFT`, `Alt`→`ALT`, `Super`/`Cmd`→`LOGO`, `Space`→`space`, `KeyK`→`k`, `Digit1`→`1`, `F1`→`F1` [s: shortcuts spec examples]. Ids: `quick-panel`, `generator`. The desktop may change the binding; `ListShortcuts` returns `trigger_description`, which Settings shows instead of the recorder on GNOME/KDE/Hyprland, with a "Change in system settings…" button calling `ConfigureShortcuts` (portal ≥ 1.21) [v]. On GNOME the `Activated` signal's `activation_token` goes to the UI as `XDG_ACTIVATION_TOKEN` (C10).

**Compositor bindings where the portal cannot.** Sway (no GlobalShortcuts backend): `bindsym Ctrl+Shift+space exec vaultkeeper --search` and `bindsym Ctrl+Shift+g exec vaultkeeper --generator`; Hyprland: either `bind = CTRL SHIFT, space, global, io.github.avbel.Vaultkeeper:quick-panel` (routes through xdph's GlobalShortcuts) or `bind = CTRL SHIFT, space, exec, vaultkeeper --search` [s: Hyprland wiki]. Settings shows the exact lines for the detected desktop (`XDG_CURRENT_DESKTOP`) with a copy button; the daemon treats a `--search`/`--generator` invocation as the hotkey (d20f31b already does).

## 11. Security chains (requirement E; BPF LSM promoted per requirement H)

**Model.** `vk_platform::security::{Chain, Link, Probe, ChainStatus}` (portable, unit-tested with fake probes):

- `Chain { id, required: Refuse | Warn | Status, minimum: LinkId, links: Vec<Link> }`, links ordered strongest first.
- `Link { id, strength, stacks: bool, probe: fn(&Env) -> Probe { Available, Degraded(why), Unavailable(why) }, activate: fn(&Env) -> io::Result<()> }`.
- Evaluation: probe every link; activate the strongest available **exclusive** link and **every** available stacking link (dumpable(0), `RLIMIT_CORE`, MDWE, mseal, mode checks stack under anything); result `ChainStatus { active, stacked, skipped: Vec<(LinkId, why)> }`; display: **Full** (top link active), **Standard** (≥ minimum), **Reduced** (below minimum → warning), **Off** (no link → refusal for `Refuse` chains unless skipped/accepted; §9).
- No chain assumes a distribution default. Links are chosen by probes at run time, on every distribution; on Arch this is the whole support story (Omarchy is the tested configuration, anything else gets what its probes find). Omarchy specifics the probes will see: `bpf` and `landlock` in the LSM list, kernel 7.2 (Landlock ABI 10), lockdown none, btrfs (verity works), the Omarchy shell as tray host **and** polkit agent, a clipboard history that skips `x-kde-passwordManagerHint` entries, xdph 1.5.0 GlobalShortcuts without tokens, UWSM so `graphical-session.target` exists, Chrome as the browser.
- Probes run at startup (< 50 ms budget), results are cached, Settings → Security has "Re-check", `vaultkeeper security status` prints the table. The BPF links share one probe (§12.9); its result is reused by every chain.

**What the probes will find on Omarchy v4.5.0** (stock; §1), chain by chain — none of it assumed, all of it probed:

| Chain | Omarchy stock result | If a user changed it |
|---|---|---|
| C1/C3/C4/C5 BPF links | `bpf` in `/sys/kernel/security/lsm` (`linux-omarchy` `CONFIG_LSM="landlock,lockdown,yama,integrity,bpf"`), BTF on; fs-verity works on the btrfs root (also under LUKS); Secure Boot off → lockdown none; the enrol prompt is answered by the Omarchy shell's polkit agent | kernel/cmdline without `bpf`: the install step prints the Limine drop-in (`/etc/limine-entry-tool.d/90-vaultkeeper.conf`: `KERNEL_CMDLINE[default]+=" lsm=landlock,lockdown,yama,integrity,bpf"`), `sudo omarchy-refresh-limine`, reboot [i: exact refresh command]; no verity on a non-btrfs/ext4-without-feature root → `tune2fs` text |
| C2 key in memory | `memfd_secret` (`CONFIG_SECRETMEM=y`) | `secretmem.enable=0` → keyctl, warned |
| C3 anti memory read | dumpable(0) + Yama 1 + BPF → Full | `linux-hardened`: Yama/userns sysctls differ → probe reports |
| C6 self-sandbox | Landlock ABI 10 (kernel 7.2) ≥ minimum 8 → Full; MDWE | `linux-lts` 6.18 → ABI 7 → Reduced |
| C7 quick unlock | FIDO2 via `uaccess` rules (systemd); fprintd only after `omarchy setup security fingerprint`; polkit `auth_self` works once the helper installs the policy (agent present) | — |
| C8 clipboard | link 1 `ext-data-control-v1`; the Omarchy clipboard history skips `x-kde-passwordManagerHint` entries | another history tool → warn text |
| C9 hotkey | link 1 xdph 1.5.0 GlobalShortcuts (no token); Settings shows the `o.bind(...)` line for `~/.config/hypr/bindings.lua` as the alternative | — |
| C10 focus | link 3 (new-window focus; no token) | — |
| C11 autostart | link 2: UWSM → `graphical-session.target` exists → our user unit; no Background portal (`hyprland;gtk`) | — |
| C12 browser identity | Chrome `/opt/google/chrome/chrome` [s], manifest `~/.config/google-chrome/NativeMessagingHosts`; `omarchy-chromium-bin` provides `chromium` | Firefox/Zen/Brave via `omarchy install browser` → their entries |
| C13 tray | Omarchy shell SNI host (`Quickshell.Services.SystemTray`) | shell killed → "no tray" |
| C14 lock/sleep | logind signals; Omarchy locks via its shell + `omarchy-sleep-lock.service` (logind inhibitor) | — |

**Chains.** Links are numbered strongest → weakest; "min" is the minimum acceptable link.

**C1 Secret files at rest** (key file, sealed tokens, cache; `Refuse`, min 3+4):
1. BPF LSM `file_open` + `path_*` hooks: under the data dir only enrolled Vaultkeeper builds and root may open, unlink, rename, truncate, link or chmod (§12.3). *Stacks with 3–5.* Probe: BPF status + canary.
2. (setgid daemon of design §5.5: **not in this chain** under Homebrew; it returns only in the deb/rpm tier if ever.)
3. AES-256-GCM sealing under HKDF(user key) — `SealedFileStore`; always on, not a probe.
4. Directory 0700 / files 0600, owner and symlink checks with repair (startup check, Unix implementation).
5. `systemd-creds --user` wrapper for the 2FA-remember token: `tpm2+host` → `host` → none (warn).
Settings text: "Full: BPF protection" / "Standard: encrypted files, private directory".

**C2 Key in memory** (`Refuse`, min 1): 1. `memfd_secret` (+ `mseal` on the mapping) → 2. kernel keyring (`keyctl`) → 3. `mlock` + zeroize. Stacking at every level: `RLIMIT_CORE=0`, `PR_SET_MDWE(REFUSE_EXEC_GAIN | NO_INHERIT)`, `umask 077`. Pattern already in `vendor/secure_memory`; the chain only surfaces which link it took (`SecureKey::backend()`).

**C3 Anti memory read** — ptrace, `/proc/<pid>/mem`, `process_vm_readv`, `pidfd_getfd` all pass through `ptrace_may_access` [v: `fs/proc/base.c`, `mm/process_vm_access.c`, `kernel/pid.c`] (`Refuse`, min 2+3):
1. BPF LSM `ptrace_access_check`: target is an enrolled Vaultkeeper task, tracer is not (and not root) → `-EPERM` (§12.3).
2. `PR_SET_DUMPABLE(0)` (stacks; always applied; same-uid non-root attach is refused by the dumpable rule [v: `kernel/ptrace.c` `task_still_dumpable`]).
3. Yama `ptrace_scope ≥ 1` (system setting, probe only; 1 on Ubuntu, 0 on Fedora).
Caveat carried from §2.2: with 2 the process's `/proc/<pid>/exe` is unreadable to peers, so clients drop dumpable **after** the handshake (C5).

**C4 Signals** (`Status` chain; warn-only): 1. BPF `task_kill`: user-initiated signals to Vaultkeeper tasks are allowed only from Vaultkeeper, the user's systemd manager, root; kernel-originated signals (tty ^C, SIGCHLD, SIGPIPE) never reach the hook [s: `check_kill_permission` returns before the LSM hook when `!si_fromuser(info)`]. 2. nothing (status "not protected"). `pkill vaultkeeper` is then denied; `vaultkeeper --quit` and `systemctl --user stop` keep working — document it.

**C5 Peer identity on the daemon's sockets** (`Refuse`, min 2):
1. BPF `unix_stream_connect` + `socket_bind` under `$XDG_RUNTIME_DIR/vaultkeeper/` (ssh socket exempt): only enrolled builds may bind or connect (§12.3).
2. `SO_PEERPIDFD` → `PIDFD_GET_INFO` (pid, uid, cgroupid) → read `/proc/<pid>/exe` **while the client is still dumpable** and compare the *file identity* (`statx` dev+ino+mnt_id, or the fs-verity digest when present) with our own → `poll(pidfd)` still alive ⇒ same process. *Stacks.*
3. `SO_PEERCRED` uid == ours. *Stacks, always.*
Client → daemon direction (CLI `cli_access.rs:212`, browser host connect `app/src/browser_host/mod.rs`; the UI uses the inherited socketpair): 1. BPF `socket_bind` gate enforcing (shared probe) → 2. socket-dir ownership + peer uid + cgroup binding (`/proc/<pid>/cgroup` ↔ `PIDFD_GET_INFO.cgroupid`, Vaultkeeper unit/scope name; Reduced when the daemon was started outside systemd) → 3. uid only. Never the daemon's `/proc/<pid>/exe`: it is non-dumpable from `Start` (1d). The daemon's hello carries version + exe identity + `deleted` flag for the "Vaultkeeper was updated" message (plan 2c).
The UI channel is not a socket path at all: an inherited `socketpair` (`--ui --ui-fd`, reusing the Windows `--ui-pipe` plumbing), so the UI link needs no peer check.

**C6 Self-sandbox** (`Warn`, min 1): 1. Landlock ruleset (ABI best-effort: fs rules for data, runtime, log, config, applications, autostart and systemd-user dirs; `SCOPE_ABSTRACT_UNIX_SOCKET` + `SCOPE_SIGNAL`; `RESOLVE_UNIX` for the D-Bus and Wayland sockets) + MDWE. 2. systemd user-unit options when started as a unit (`NoNewPrivileges`, `MemoryDenyWriteExecute`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`, `RestrictNamespaces`, `LockPersonality`, `RestrictRealtime`, `SystemCallFilter=@system-service`; no `PrivateUsers`). 3. none. Note: Landlock implies `no_new_privs`, so the daemon can never run `pkexec`; that is why the root helper is a D-Bus service (§12.5).

**C7 Quick unlock / key at rest** (`Status`; a feature, not a protection): 1. FIDO2 `hmac-secret` (envelope v2 primitive id 6; UV or PIN) → 2. (TPM2 sealed + PIN: later, `tss-esapi` is still 8.0.0-alpha) → 3. in-memory key + fprintd/polkit presence check → 4. none (master password). With the BPF helper installed, 3 gets our own polkit action (`auth_self`).

**C8 Clipboard concealment** (`Status`, min 3): 1. `ext-data-control-v1` via `wl-clipboard-rs` 0.9.5 with `x-kde-passwordManagerHint=secret` and the timed clear (KDE, Sway, Hyprland) → 2. RemoteDesktop + Clipboard portal (GNOME; persisted `restore_token`, `persist_mode` 2; Bitwarden's `portal_backend.rs` is the template) → 3. `arboard` plain set + timed clear (warn: history managers may record).

**C9 Global hotkey** (`Status`): 1. GlobalShortcuts portal (GNOME, KDE, Hyprland) → 2. compositor binding running `vaultkeeper --search` (Sway; Hyprland alternative) → 3. none: Settings shows the lines to add.

**C10 Quick Panel focus** (`Status`): 1. `activation_token` from the portal (GNOME) → 2. token from the launcher (`XDG_ACTIVATION_TOKEN` set by the compositor for `exec` bindings — Sway/Hyprland do not set it [i]) → 3. new-window focus (default on Sway/Hyprland; KWin at default focus-stealing level [i]) → 4. keep the UI process alive and `request_activation_token()` from it.

**C11 Autostart** (`Status`): 1. Background portal `RequestBackground{autostart, commandline}` (GNOME, KDE) → 2. the app's own `~/.config/systemd/user/io.github.avbel.Vaultkeeper.service` bound to `graphical-session.target` (Sway/Hyprland with uwsm or sway-systemd) → 3. `~/.config/autostart/io.github.avbel.Vaultkeeper.desktop` (GNOME/KDE honour it; Sway/Hyprland only with `dex`) → 4. printed `exec vaultkeeper --tray` / `exec-once = vaultkeeper --tray`.

**C12 Browser host identity** (`Status`): 1. BPF connect gate (the host *is* an enrolled build) + 2. parent chain through `xdg-native-messaging-proxy` (argv `[path, manifest, extension id]`) → 3. direct browser parent by executable path (incl. `/snap/firefox/*/usr/lib/firefox/firefox`) → 4. unknown → ask the user (today's behaviour).

**C13 Tray** (`Status`): 1. StatusNotifierItem via ksni (KDE, waybar on Sway/Hyprland, GNOME with the AppIndicator extension) → 2. none: Settings notice "no tray on this desktop; use the shortcut or the launcher entry".

**C14 Lock, sleep, session end** (`Status`): 1. logind `PrepareForSleep`, `PrepareForShutdown`, session `Lock`/`Unlock` and `LockedHint` → 2. `org.freedesktop.ScreenSaver` `ActiveChanged` (KDE) / `org.gnome.ScreenSaver` (GNOME) → 3. idle timeout only.

## 12. BPF LSM as the first link (requirement H)

### 12.1 Availability on the floor

All three floor kernels (Ubuntu 7.3, Fedora 7.3.5, Omarchy `linux-omarchy` 7.2.15) have `bpf` in `CONFIG_LSM`, `CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_SECURITY_PATH=y`, `CONFIG_FS_VERITY=y` [v: §1]. Other Arch kernels (`linux-lts`, `linux-hardened`, custom) are not assumed: the probe decides, and the Omarchy VM swaps kernels to prove the fallback. Probe: `/sys/kernel/security/lsm` contains `bpf` (securityfs is mounted by systemd on both; the file is world-readable [s]). Ubuntu 26.04 LTS (out of the floor) lacks it: the helper's `install` would append `lsm=landlock,lockdown,yama,integrity,apparmor,bpf` to `GRUB_CMDLINE_LINUX_DEFAULT`, run `update-grub` and ask for a reboot; documented, not tested.

### 12.2 Secure Boot and lockdown

With Secure Boot on, both kernels enter lockdown **integrity** mode (`LOCK_DOWN_IN_SECURE_BOOT` / `LOCK_DOWN_IN_EFI_SECURE_BOOT` = y; `FORCE_NONE` otherwise) [v]. Integrity blocks `LOCKDOWN_BPF_WRITE_USER` only (it sits before `LOCKDOWN_INTEGRITY_MAX`); `LOCKDOWN_BPF_READ_KERNEL` and `LOCKDOWN_KPROBES` are confidentiality-level [v: `include/linux/security.h` v7.3]. Loading BPF LSM programs, kfunc calls, maps and pinning are not lockdown reasons at all. Our programs read kernel structures through BTF-typed pointers, not `bpf_probe_read_kernel`, so even confidentiality mode would not stop them [i]. Omarchy: Arch kernels carry no Secure-Boot-lockdown patch and Omarchy enrols no SB keys (Limine UKI, no sbctl), so lockdown is **none** and SB is off on a stock install [v]; nothing to test there beyond "off". Test both SB states on Fedora (`vm-fedora-gnome`) anyway (§12.10).

### 12.3 Programs (C, libbpf; `lsm/` or `lsm.s/`)

Identity primitive `is_vaultkeeper(task)`: `bpf_get_task_exe_file(task)` → `bpf_get_fsverity_digest(file, &digest)` → lookup in the `enrolled` hash map (key = 32-byte digest; value = version, enrolled-at). Both kfuncs are non-sleepable and LSM-only [v: `measure.c` filter `prog->type != BPF_PROG_TYPE_LSM`; `bpf_fs_kfuncs.c` `KF_ACQUIRE|KF_RET_NULL`]. A file without verity returns `-ENODATA` → not Vaultkeeper. Cache the verdict per task in a `BPF_MAP_TYPE_TASK_STORAGE` filled on `lsm/bprm_committed_creds` (one measurement per exec), so the hot hooks do one map lookup.

| Hook | Decision | Notes |
|---|---|---|
| `lsm.s/file_open`, `lsm.s/path_unlink`, `path_rename`, `path_truncate`, `path_link`, `path_symlink`, `path_mkdir`, `path_rmdir`, `path_chmod`, `path_chown` | if the inode's `i_uid` is an enrolled uid **and** `bpf_path_d_path` has a protected prefix (`prefixes` map: uid → data dir) **and** caller is not Vaultkeeper and not uid 0 → `-EPERM` | the uid pre-check keeps `d_path` off the hot path for everyone else; `bpf_path_d_path` is usable from any LSM hook [v: `bpf_fs_kfuncs_filter`], unlike `bpf_d_path` (allowlist of 10 hooks [v: `bpf_trace.c`]) |
| `lsm/ptrace_access_check(child, mode)` | child is Vaultkeeper, current is not and not root → `-EPERM` | covers attach, `/proc/pid/mem`, `process_vm_*`, `pidfd_getfd`, and `/proc/pid/exe` of our processes |
| `lsm/task_kill(p, info, sig, cred)` | p is Vaultkeeper; sender not Vaultkeeper, not root, not the user's `systemd --user` (exe path `/usr/lib/systemd/systemd` via `bpf_path_d_path`, parent pid 1) → `-EPERM` | kernel-originated signals never hit the hook [s] |
| `lsm/unix_stream_connect(sock, other, newsk)` | listener path (`unix_sk(other)->addr->name`) under `prefixes[uid].runtime` (`/run/user/<uid>/vaultkeeper/`) except `ssh.sock`; caller not Vaultkeeper and not root → `-EPERM` | the ssh socket must stay open to `ssh`/`git`; per-request approval guards it |
| `lsm/socket_bind(sock, address, len)` | `AF_UNIX` path under the runtime prefix, caller not Vaultkeeper → `-EPERM` | stops socket squatting before the daemon starts |
| `lsm/bprm_committed_creds(bprm)` | measure `bprm->file`, store verdict in task storage | also marks the UI/CLI/host processes |

Everything else returns 0 after at most one map lookup: **fail-open except Vaultkeeper's own files, sockets and tasks**. Empty maps (helper installed, no user enrolled) enforce nothing.

### 12.4 Binary identity: signed fs-verity digest

- The release pipeline computes `fsverity digest` of the exact `vaultkeeper` ELF and signs it with the release minisign key (`vaultkeeper.verity.minisig`, same key as the updater). The root helper verifies that signature in user space, enables verity on the file (`FS_IOC_ENABLE_VERITY`, SHA-256, 4 KiB blocks), re-measures (`FS_IOC_MEASURE_VERITY`) and inserts the digest into the root-owned `enrolled` map. A `brew upgrade` produces a new file → new digest → prompt → enrol; the digest, not the path, is the identity, so the Cellar move is irrelevant.
- The kernel's own pattern verifies in-kernel instead: `bpf_get_fsverity_digest` + `bpf_get_file_xattr(f, "user.sig")` + `bpf_lookup_user_key(serial)` + `bpf_verify_pkcs7_signature` [v: `tools/testing/selftests/bpf/progs/test_sig_in_xattr.c` v7.3]. It needs an X.509 certificate with an RSA/ECDSA key (the kernel's PKCS#7 has no Ed25519 [s]) in a keyring every process may search, and the `user.sig` xattr on a user-writable file. Recommendation: **helper-side verification + root-owned map first**; in-kernel PKCS#7 is a later hardening that removes trust in the helper's user-space check (open decision 4).
- Filesystems: btrfs (Fedora `/home`, `/`) supports fs-verity without a format flag [s: kernel fs-verity docs]; ext4 needs the `verity` feature, which `mke2fs` does not set by default [v: `mke2fs.conf.in`] and Ubuntu's installer does not add [i]; `tune2fs -O verity <dev>` sets it on the superblock but the running kernel only sees it after a remount/reboot [i], and it needs block size = page size (4 KiB, both) [s]. The Homebrew prefix is on `/home` (Fedora: btrfs subvolume, fine) or `/` (Ubuntu: ext4) → on Ubuntu `install` detects the missing feature (try `FS_IOC_ENABLE_VERITY` on a temp file → `EOPNOTSUPP`), prints the `tune2fs` command, and requires a reboot before enrolment. Verity files are read-only forever; deletion still works (brew cleanup). Omarchy is btrfs (snapper), so verity works without preparation; the Homebrew prefix lives on that same filesystem [v: snapper config; i: subvolume layout]. **Verify in the VMs**: Fedora btrfs (`vm-fedora-gnome`), Ubuntu ext4 default install (`vm-kubuntu`), Omarchy btrfs under LUKS (`vm-omarchy`), the Homebrew prefix path on each.

### 12.5 Rootless app, one-time privileged helper

The app never runs as root and never execs a setuid binary (Landlock/`no_new_privs`, §11 C6). The helper `vaultkeeper-bpf` (own crate, static musl, no GUI deps) is installed once with `sudo vaultkeeper security install` (which prints and runs `sudo <opt>/libexec/vaultkeeper-bpf install`):

- copies itself to `/usr/local/libexec/vaultkeeper/vaultkeeper-bpf` (root-owned; never run from the user-writable prefix);
- installs `/etc/systemd/system/vaultkeeper-bpf.service` (`Type=oneshot`, `RemainAfterExit=yes`, `ExecStart=… load`, `ExecStop=… unload`; programs stay attached through pinned links under `/sys/fs/bpf/vaultkeeper/` after the loader exits [s]) and a D-Bus **system service** `io.github.avbel.VaultkeeperBpf` (`/usr/share/dbus-1/system.d/*.conf`, `system-services/*.service`, activated on demand) with methods `Enroll(path)`, `Register(uid, data_dir, runtime_dir)`, `Status()`, each guarded by a polkit check (`io.github.avbel.vaultkeeper.bpf.enroll`: `auth_admin_keep`; `register`: `yes` for the active session) — the daemon talks to it over zbus and polkit shows the system dialog; no `pkexec`;
- installs `/usr/share/polkit-1/actions/io.github.avbel.vaultkeeper.policy` (also the quick-unlock `auth_self` action of C7);
- enables verity on the current binary, verifies the signature, enrols the digest; registers the calling user's data and runtime dirs;
- when `/sys/kernel/security/lsm` lacks `bpf`, stops and prints the exact command-line change for the detected system: Omarchy → the Limine drop-in `/etc/limine-entry-tool.d/90-vaultkeeper.conf` with `KERNEL_CMDLINE[default]+=" lsm=landlock,lockdown,yama,integrity,bpf"` + `sudo omarchy-refresh-limine` + reboot [i: refresh command]; Ubuntu (26.04) → `GRUB_CMDLINE_LINUX_DEFAULT` + `update-grub`; Fedora → `grubby --update-kernel=ALL --args="lsm=…"`; other → "add `bpf` to the `lsm=` list of your bootloader"; a stock Omarchy never hits this (bpf is in the list);
- pins maps: `enrolled` and `status` 0644 (readable by users), `prefixes` 0600.

Subcommands: `install`, `update` (re-copy helper, reload programs if their version changed), `enroll <path>`, `verify` (prints programs, maps, canary results), `uninstall` (stop, unpin, remove files), `load`/`unload` (unit). Recovery: `sudo systemctl stop vaultkeeper-bpf` → everything allowed at once; at boot `systemd.mask=vaultkeeper-bpf.service` on the kernel command line; the daemon itself never fails hard on a BPF denial of *its own* file — the startup probe reports "installed, this build not enrolled → Enroll…" before it touches the data dir.

### 12.6 Safety

Hot-path cost: one task-storage lookup per hook; `d_path` only for files owned by enrolled uids. Measure `openat` latency in the spike (4a) with and without the programs. Verifier: bounded prefix compares over 256-byte buffers. The helper's `load` refuses to attach if the kernel lacks any kfunc it needs (CO-RE + `bpf_core_type_exists`), and logs to the journal.

### 12.7 Implementation choice

`libbpf-rs` 0.27.2 + `libbpf-cargo` (C programs, skeletons, `vmlinux.h` vendored from a Fedora 45 BTF dump; CO-RE keeps it portable) over `aya` 0.16 (Rust-only eBPF; kfuncs, sleepable LSM and task storage are less travelled there [i]). The kernel selftests for exactly these kfuncs are C and port directly. CI (`ubuntu-latest`) gets `clang llvm libelf-dev zlib1g-dev bpftool`; `libbpf-sys` with the `vendored` feature links statically. GPL license of the project matches the GPL-only kfunc/helper requirements.

### 12.8 What it adds, what it does not

Adds over setgid (design §5.5): works under Homebrew (no root at *app* install); blocks same-uid reads of the key file and tokens, ptrace and memory reads even while dumpable, socket squatting and impostor connects, moving the data directory aside; identity is cryptographic (release-signed digest), not a path or a gid. Still not covered: root; kernel exploits; malware driving the genuine CLI, browser host or UI (→ per-request confirmation: `polkit auth_self`/UI confirm for CLI reveals, SSH signing, browser fills — the existing settings); the compositor (sees everything the UI shows and types); the window before the helper is installed; self-built binaries (`enroll --unsigned` for developers prints a loud warning and marks the status "developer build").

### 12.9 Probes and status

Daemon: `/sys/kernel/security/lsm` has `bpf`; `/sys/fs/bpf/vaultkeeper/status` readable and says `enforcing`; own digest (`FS_IOC_MEASURE_VERITY` on `/proc/self/exe`; `ENODATA` → not enrolled) ∈ `enrolled`; **functional canary**: write `data_dir/.canary`, `posix_spawn("/bin/cat", data_dir/.canary)` with a 1 s timeout → expected `EACCES`/`EPERM` → "BPF protection active (verified)". Settings → Security row: "BPF protection: **active** · enforcing · this build enrolled" / "installed — this build not enrolled → **Enroll…**" / "available — not installed → **Install…** (asks for the administrator password)" / "unsupported — `lsm=` lacks `bpf`".

### 12.10 VM verification matrix

`vm-fedora-gnome` (btrfs, Secure Boot **on** and **off**), `vm-kubuntu` (ext4, SB on and off if the hypervisor allows), `vm-fedora-sway`, `vm-omarchy` (btrfs + LUKS, SB off, lockdown none; then `pacman -S linux-lts` and `linux-hardened`, `omarchy kernel set <kernel>`, reboot: the chains must report the weaker links or refuse with the exact item) (hypervisor with UEFI Secure Boot; record `mokutil --sb-state` and `/sys/kernel/security/lockdown`). Per VM: `install` (Ubuntu: the `tune2fs -O verity` + reboot path), `verify`, canary denied; `cat` of the key file denied as the user and allowed as root; `gdb -p`, `cat /proc/<pid>/mem`, `process_vm_readv` tool denied; `kill -STOP`, `pkill vaultkeeper` denied, `vaultkeeper --quit` and `systemctl --user stop` work, Ctrl+C in the CLI works; `socat` connect to `cli.sock` denied, `ssh-add -l` works; `brew upgrade` → prompt → enrol → restart; `uninstall` → everything allowed again; reboot persistence; `openat` latency before/after.

## 13. Sources

Primary (fetched 2026-11-20):

- Ubuntu 26.10 and 26.04 release notes (documentation.ubuntu.com); Launchpad API `getPublishedSources` for linux, systemd, xdg-desktop-portal, policykit-1, dbus-broker, gnome-shell, mutter, firefox, xdg-native-messaging-proxy; Launchpad kernel git `stonking` and `resolute` (`master`) `debian.master/config/annotations`.
- Fedora 45 announcement (fedoramagazine.org); mdapi.fedoraproject.org f45 for kernel, systemd, xdg-desktop-portal(-gnome/-kde), polkit, dbus-broker, gnome-shell, mutter, plasma-workspace, xdg-native-messaging-proxy; `kernel-x86_64-fedora.config` (f45); `tpm2-tss.spec`; Fedora wiki Change "Restrict ptrace for unprivileged users…" (rejected).
- archlinux.org package pages/JSON for systemd, linux, xdg-desktop-portal*, polkit, dbus-broker, plasma-workspace, gnome-shell, sway, hyprland; AUR RPC for xdg-native-messaging-proxy.
- Debian madison for systemd, xdg-desktop-portal(-gnome/-kde), polkitd, dbus-broker, linux-signed-amd64, gnome-shell, plasma-workspace, sway, hyprland, xdg-native-messaging-proxy; sources.debian.org `linux 7.3.4-1 debian/config/config`, `tpm-udev 0.6+nmu1 debian/tpm-udev.udev`.
- kernel.org front page and tags; `include/uapi/linux/pidfd.h` (v6.12, 6.13, 6.15, 6.16, 7.3), `include/uapi/asm-generic/socket.h` (v6.5), `include/uapi/linux/prctl.h` (v6.2, 6.3, 7.3), `include/uapi/linux/landlock.h` (v7.3), `security/landlock/syscalls.c` (v6.12, 6.18, 7.0–7.3), `security/yama/yama_lsm.c` (v7.3), `kernel/ptrace.c`, `fs/proc/base.c`, `net/core/sock.c` (v7.3); docs.kernel.org Landlock, mseal, fs-verity; man7 `memfd_secret(2)`, `pidfd_open(2)`, `unix(7)`, `dh_installsystemduser(1)`.
- systemd v262: `man/systemd.exec.xml`, `man/systemd-creds.xml`, `NEWS` (256–262), `rules.d/70-uaccess.rules.in`, `rules.d/50-udev-default.rules.in`, `src/rpm/macros.systemd.in`, `triggers.systemd.in`, `systemd-update-helper.in`; GitHub release list.
- xdg-desktop-portal 1.22.1: release notes 1.18–1.22, `data/org.freedesktop.host.portal.Registry.xml`, `…GlobalShortcuts.xml`, `…RemoteDesktop.xml`, `…Clipboard.xml`, `…Background.xml`, `data/` listing; PR #705 state. xdg-desktop-portal-gnome 51.0 `src/globalshortcuts.c`, `src/clipboard.c`; xdg-desktop-portal-kde Plasma/6.8 `src/` listing and `globalshortcuts.cpp`; xdg-desktop-portal-hyprland `src/portals/` and `GlobalShortcuts.cpp`; xdg-desktop-portal-wlr README.
- xdg-native-messaging-proxy: README, release 0.1.0, `src/xnmp-impl.c`; Firefox source docs "Native messaging for a strictly-confined Firefox"; mozilla-firefox/firefox `NativeMessaging.sys.mjs` at FIREFOX_156/157/158_0_RELEASE and `StaticPrefList.yaml`; whattrainisitnow release schedule.
- polkit `NEWS.md` (124), `docs/man/polkit.xml`, `src/polkit/polkitunixprocess.c`; dbus-broker `NEWS.md` (34), bundled `dbus-specification.xml` (`ProcessFD`).
- GNOME 51 release notes; KDE Plasma 6.7.0 and 6.8.3 announcements; Sway 1.12 release notes; Hyprland release list; ubuntu/gnome-shell-extension-appindicator `metadata.json` and releases; extensions.gnome.org listing #615.
- tpm2-software/tpm2-tss `dist/tpm-udev.rules`; debhelper `autoscripts/postinst-systemd-user-restart`; init-system-helpers `deb-systemd-invoke`.
- Local code: `crates/platform/src/hardening.rs`, `crates/ipc/src/transport/unix.rs`, `crates/ipc/src/peer.rs`, `crates/ipc/src/cli_access.rs`, `vendor/secure_memory`, `Cargo.lock`; cargo registry sources of `authenticator` 0.5.0, `winit` 0.30.13, `i-slint-backend-selector` 1.19.0, `i-slint-core` 1.19.0, `libc` 0.2.191, `rustix` 1.1.6; docs.rs `ksni` 0.3.7 `Tray`; `cargo search` for ashpd 0.14.1, landlock 0.4.7, seccompiler 0.5.0, tss-esapi 8.0.0-alpha.4, wl-clipboard-rs 0.9.5, zbus 6.4.0, pidfd 0.2.4; Bitwarden `desktop_native/core/src/{process_isolation/linux.rs, ipc/mod.rs, clipboard/portal_backend.rs}`.

- Homebrew: `docs.brew.sh/Homebrew-on-Linux`, `Formula-Cookbook`, `FAQ`; Homebrew/brew `Library/Homebrew/service.rb` (`to_systemd_unit`), `services/system.rb`, `services/formula_wrapper.rb`, `formula_installer.rb` (`install_service`), `upgrade.rb`; avbel/homebrew-tap `Formula/yrem.rb` and the `Formula/` listing (gh api, 2026-11-20).
- Ubuntu stonking/resolute: Launchpad `getPublishedSources` for plasma-workspace, kwin, sway, hyprland, xdg-desktop-portal-{kde,hyprland,wlr,gtk}, waybar, swaylock, swayidle, hyprlock, hypridle, hyprpolkitagent, gnome-shell-extension-appindicator; stonking `debian.master/config/annotations` (`CONFIG_LSM`, `BPF_LSM`, `DEBUG_INFO_BTF`, `FS_VERITY*`, `LOCK_DOWN_*`, `SECURITY_PATH`, `BPF_UNPRIV_DEFAULT_OFF`).
- Fedora 45: mdapi for the same desktop packages plus fsverity-utils, bpftool, libbpf; `kernel-x86_64-fedora.config` (f45) for `CONFIG_LSM`, `BPF_LSM`, `FS_VERITY`, `FS_VERITY_BUILTIN_SIGNATURES`, `LOCK_DOWN_*`, `SECURITY_PATH`, `SECONDARY_TRUSTED_KEYRING`; COPR API (`solopasha/hyprland` builds and chroots; project search "hyprland").
- Kernel v7.3: `include/linux/security.h` (lockdown reasons), `fs/verity/measure.c` (`bpf_get_fsverity_digest`, LSM-only filter), `fs/bpf_fs_kfuncs.c` (`bpf_get_task_exe_file`, `bpf_path_d_path`, `bpf_get_file_xattr`, xattr prefixes, LSM filter; file first appears in v6.12), `kernel/bpf/helpers.c` (`bpf_lookup_user_key`, `bpf_lookup_system_key`, `bpf_verify_pkcs7_signature`), `kernel/trace/bpf_trace.c` (`btf_allowlist_d_path`), `tools/testing/selftests/bpf/progs/test_sig_in_xattr.c`; e2fsprogs `misc/mke2fs.conf.in`, `misc/tune2fs.c`.
- xdg-desktop-portal-wlr and xdg-desktop-portal-hyprland GitHub releases (1.5.0, 1.4.1); `org.freedesktop.portal.GlobalShortcuts.xml` (`preferred_trigger`, `trigger_description`).
- Omarchy: basecamp/omarchy `quattro` (tags v4.5.0; `bin/omarchy-kernel`, `etc/limine-entry-tool.d/*.conf`, `default/limine/limine.conf`, `config/xdg-desktop-portal/hyprland-portals.conf`, `install/omarchy-base.packages`, `install/user/chromium.sh`, `install/user/first-run/*`, `default/hypr/{autostart,envs}.lua`, `default/hypr/bindings/*.lua`, `shell/plugins/{bar/widgets/Tray.qml,polkit/PolkitAgent.qml,clipboard/capture.sh}`, `default/systemd/user/omarchy-sleep-lock.service`); omacom-io/omarchy-iso (`builder/archinstall.packages`, `configs/airootfs/root/configurator`, `disk-partitioning.sh`); omacom-io/omarchy-pkgs (`pkgbuilds/linux-omarchy/{PKGBUILD,config.x86_64}`, `pkgbuilds/hyprland/PKGBUILD`, `pkgbuilds/omarchy-chromium-bin/PKGBUILD`); archlinux.org package JSON (linux, linux-lts, linux-hardened, hyprland, xdg-desktop-portal*, waybar, hyprpolkitagent, polkit, systemd, limine, fsverity-utils, libbpf, chromium); Fedora `sway-config-fedora.spec` (f45).
- Local code: `app/src/settings.rs` (`auto_update`, `DEFAULT_HOTKEY`, `hotkey_display`), `app/src/hotkey_recorder.rs`, `app/src/app/settings_hotkeys.rs`, `app/src/daemon/update/{mod.rs,install_unavailable.rs,setup_policy.rs}`, `app/ui/settings.slint`, `app/src/os/startup_check.rs`, `crates/platform/src/fs.rs`, `app/src/browser_status.rs`, `app/src/cli.rs`, `.plan/windows-support.md`, `docs/solutions/windows-test-checklist.md`, `docs/solutions/linux-gaps.md` "Decisions".

Secondary: Arch forum posts quoting `CONFIG_LSM`; snapcraft forum thread on confined browser native messaging (2021); siemens/linux-entra-sso README (Firefox Flatpak + proxy); extensions.gnome.org GNOME 51 note; CTAP2 PIN retry limit (from memory of the spec, not re-read).
