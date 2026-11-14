# Vaultkeeper on Linux (Wayland only): research

Scope: GNOME, KDE Plasma 6, Sway, Hyprland. No X11. Date: 2026-11-13.
Marks: **[v]** = checked in a primary source or in code during this research; **[i]** = inferred or from memory, check on a real machine; **[f]** = from the Fable second opinion (2026-11-14) with a cited source, not re-checked.

## 0. Short answers

| Question | Answer |
|---|---|
| How hard? | Medium. The vault, crypto, API, SSH agent and CLI are already portable. The work is Wayland fragmentation: hotkeys, focus, clipboard, auto-type and tray differ per desktop. Estimate: MVP 6–8 weeks, parity with macOS 14–18 weeks (one developer, see §9). |
| Hide Touch ID where it is missing? | Yes. Most of the gating exists (`touch-id-available`), but some controls ignore it (§3.4). |
| "Two solutions" for fingerprint | (1) **fprintd** over D-Bus directly; (2) **polkit → PAM** (pam_fprintd, and through PAM also Howdy face unlock, pam_u2f or the login password). Both answer only yes/no and never release a key. Decided: polkit → PAM, so the system's PAM setup picks the method (§3.2). |
| Tray on KDE and GNOME | One implementation, StatusNotifierItem (`ksni`, already in Cargo.lock through Slint). KDE: native. GNOME: only with the AppIndicator extension (Ubuntu ships it, vanilla GNOME such as Fedora does not). |
| Black and white icons enough? | No. Slint sends only a raster pixmap, so panels cannot recolour it, and bar colours vary on Sway/Hyprland. Use a symbolic icon name plus a pixmap fallback, and add a blue colour choice (§4). |
| Key at rest that only Vaultkeeper can decrypt (restart without master password)? | No LSM, portal, keyring or TPM gives it to an unconfined same-uid process. A **setgid daemon** with a group-owned key half does, for .deb/.rpm/AUR installs only (§5.5). BPF LSM could harden it later (§5.6). |
| Need gnome-keyring / KWallet? | No, and better to avoid them. Seal the refresh token under a key derived from the vault user key (§5). |
| TPM 2.0? | Not in v1. It only binds data to the machine, which adds little once the tokens are sealed under the user key. Later it is the right base for a PIN unlock with hardware anti-hammering. An emulated TPM (swtpm) adds no security; use it only for CI. |
| Sway and Hyprland? | Yes, with a few documented config lines (hotkey, autostart, floating rule, lock command, polkit agent). |

## 1. What changes compared with the README roadmap

| README "Phase 2: Linux" says | Research result |
|---|---|
| Refresh tokens in Secret Service (libsecret) | Drop it. Seal the refresh token under a key derived from the user key, in a 0600 file; the 2FA-remember token needs a separate choice (§5). Verified safe: tokens are used only while unlocked (`crates/vault/src/vault/background.rs` aborts sync, websocket and probe on lock; `sync.rs` refreshes only in an unlocked ctx). |
| Autostart through a freedesktop `.desktop` file | GNOME/KDE: XDG autostart or the Background portal. Sway/Hyprland do not run XDG autostart by default (except under uwsm). Document `exec`/`exec-once`. |
| IPC peer check with `SO_PEERCRED` plus an executable check | Keep it, but compare `/proc/<pid>/exe` by (st_dev, st_ino) rather than by path (today's non-macOS path compares the canonical path), use `SO_PEERPIDFD` on kernel 6.5+, and treat it as a mistake guard, not a security boundary (§7.6). |
| Clipboard and global hotkeys for X11 and Wayland | X11 dropped. `global-hotkey` is X11-only on Linux [v: its Linux deps are x11rb/xkeysym], so it goes. Hotkeys come from the GlobalShortcuts portal, or `vaultkeeper --quick` bound in the compositor. The clipboard needs Wayland data-control, because the daemon (windowless) owns it (§7.3). |
| Biometrics through polkit/fprintd, or none | Concrete design: polkit check (PAM: fingerprint, Howdy, security key or login password), key kept in non-dumpable `memfd_secret` memory, master password after every daemon restart (§3), unless the setgid daemon's persistent mode is installed (§5.5). |
| The Unix-socket SSH agent already works | True. Default socket should move to `$XDG_RUNTIME_DIR/vaultkeeper/ssh-agent.sock`. On GNOME, `gcr-ssh-agent` already claims `SSH_AUTH_SOCK`, so document the override. |
| (missing) | Tray via `ksni` directly with symbolic icon and colour choice; Quick Panel focus needs xdg-activation tokens; auto-type through the RemoteDesktop portal (GNOME/KDE) and virtual-keyboard protocol (Sway/Hyprland); lock detection through logind; startup permission checks; Linux updater signature. |

## 2. Desktop support matrix

| Feature | GNOME 46 (Ubuntu 24.04) | GNOME 48/49+ | KDE Plasma 6 | Sway | Hyprland |
|---|---|---|---|---|---|
| Tray (SNI) | Only with the AppIndicator extension; Ubuntu enables it [i] | Same [i] | Native [v] | swaybar: icon, **no menu** (dbusmenu PRs #6249, #8920 still open) [v]; Waybar: menu works | Waybar tray [v] |
| Global hotkey | No portal [v: Hex docs]. Fallback: write a GNOME custom shortcut running `vaultkeeper --quick` | GlobalShortcuts portal [v: ArchWiki table]; first GNOME version 48 [i] | Portal, with a "Global Shortcuts Requested" dialog [v] | No portal [v]. `bindsym … exec vaultkeeper --quick` | Portal registers the name; the user binds the key in config (`global, <appid>:quick`) [v] |
| Daemon clipboard set + auto-clear (data-control) | No data-control [v] | ext-data-control from GNOME 49 [i: secondary source citing wayland.app] | Yes [v] | Yes [v] | Yes [v] |
| Hide from clipboard history (`x-kde-passwordManagerHint: secret`) | Unknown | Unknown | Klipper honours it [v] | cliphist honours it (via `wl-paste --watch`) [v] | Same [v] |
| Auto-type | RemoteDesktop portal [v] | Same [v] | Same [v] | `zwp_virtual_keyboard_v1` [v] | Same [v] |
| Quick unlock via polkit (PAM) | Agent built in | Same | Agent built in | User must run an agent | `hyprpolkitagent` (usually installed) [i] |
| Screen-lock signal | `org.gnome.ScreenSaver.ActiveChanged` [v: Bitwarden code] | Same | `org.freedesktop.ScreenSaver.ActiveChanged` [v] | logind `Session.Lock` when the locker is started through `loginctl lock-session` [i] | Same (hypridle's usual config does this) [i] |
| `systemd-creds --user` | No, systemd 255 [i] | Distro-dependent | Distro-dependent | Distro-dependent | Distro-dependent |

Support floor to decide: Ubuntu 24.04 (GNOME 46) lacks the shortcuts portal, data-control and `systemd-creds --user` at once, and it is the largest install base. Either support it with fallbacks (custom-keybinding writer, copy from the focused UI process, no guaranteed auto-clear) or set the floor at GNOME 48/49.

## 3. Fingerprint unlock ("Touch ID" on Linux)

### 3.1 The two paths

- **fprintd directly** (`net.reactivated.Fprint` on the system bus: `Manager.GetDefaultDevice` → `Device.Claim("")` → `VerifyStart("any")` → `VerifyStatus` signal → `Release`). Polkit action `net.reactivated.fprint.device.verify` is `allow_active=yes` [v: fprintd policy file], so any app in the active session can verify with no prompt and nothing to install. Fingerprint only; the app draws its own "touch the sensor" UI and must handle "device busy" (the lock screen may hold the reader).
- **polkit** (`CheckAuthorization` on a custom action, `allow_active=auth_self`). The system draws the prompt and runs PAM, so one code path covers pam_fprintd, Howdy (IR face), pam_u2f security keys and the login password. Needs the `.policy` file in `/usr/share/polkit-1/actions` (root: shipped by .deb/.rpm/AUR; Bitwarden's AppImage installs it once with `pkexec`) [v: Bitwarden source], and a running polkit agent (built into GNOME/KDE; Sway users must start one).

Neither path releases key material. This is the key difference from macOS, where the Secure Enclave key cannot be used without a matching finger.

### 3.2 Decision: polkit (PAM)

Quick unlock goes through polkit only (the design review's recommendation, accepted). Reasons:

- One code path covers every method the system's PAM setup offers: fingerprint (pam_fprintd), Howdy face unlock, pam_u2f security keys and the login password.
- The system draws the prompt, and PAM applies its own retry limits.
- Vaultkeeper never talks to fprintd directly, so there is no "touch the sensor" UI, attempt counting or "device busy" handling to build.

Consequences to accept and document:

- The feature is "system authentication", not "fingerprint". It is available on a machine without a reader, where it unlocks with the login password.
- Whether the prompt asks for a finger depends on the distro's PAM stack for `polkit-1`. It includes pam_fprintd only when fingerprint login was enabled (`pam-auth-update` on Ubuntu, `authselect … with-fingerprint` on Fedora) [i].
- It needs the policy file in `/usr/share/polkit-1/actions`. The .deb, .rpm and AUR packages ship it. The AppImage offers a one-time `pkexec` install, as Bitwarden does.
- It needs a polkit agent. GNOME and KDE have one built in; Hyprland usually runs `hyprpolkitagent`; Sway users must start one (§7.9).

Not built: direct fprintd (`net.reactivated.Fprint`). It would only add "works without a policy file or agent". The only optional use is a read-only probe of `Device.ListEnrolledFingers` to show a fingerprint icon on the button.

Either path gates the same in-memory key (§3.3). In both, Vaultkeeper's daemon releases the key after a yes from a root daemon.

### 3.3 Security model (Bitwarden's "ephemeral path")

- After one master-password unlock, the daemon keeps the user key in `vendor/secure_memory` (memfd_secret, then keyctl, then mlock) and calls `prctl(PR_SET_DUMPABLE, 0)`. That blocks ptrace and `/proc/<pid>/mem` from same-uid processes and keeps the key out of core dumps.
- Lock zeroizes the vault crate's working copy but keeps the sealed key in that store. That breaks the macOS invariant "locking zeroizes the user key". Proposed UI wording: "While quick unlock is on, the locked vault keeps its key in protected memory, never on disk. Quitting Vaultkeeper or restarting the computer discards it, and the next unlock needs your master password." Turning quick unlock off zeroizes at once.
- **No persistent mode through Secret Service or systemd-creds.** Both are readable by any same-uid process without any user check, so a "survives restart" mode built on them would not be gated by the polkit check (Bitwarden ships one only behind a warning). The only sound persistent mode is the setgid daemon (§5.5); where it is not installed (AppImage), hide "Require master password on app start": it is always effectively on.
- Covers: someone at an unattended machine with a locked vault; memory scraping by same-uid apps. Does not cover: a same-uid process using the daemon's socket, root, the kernel.

### 3.4 Hiding Touch ID options: concrete spots

Today's gating exists (`touch-id-available`, filled from `biometrics.is_available()`), but:

- `app/ui/settings.slint:242` — the enrol row always renders and says "Touch ID is not available". Hide the whole block.
- `app/ui/settings.slint:257` — "Unlock with Touch ID right away" is only disabled, not hidden.
- `app/ui/settings.slint:331` — "SSH requires Touch ID" has no gate at all.
- `app/ui/settings.slint:236` — "Require master password on app start" ("Off: Touch ID alone unlocks after a restart") is meaningless without a persistent mode. Hide it on Linux.
- Hardcoded text in `settings.slint:237, 402, 408`, `auth.slint:111-112`, `quick.slint:173`, `ssh.slint:107` and `browser_picker.slint:130` → a `biometric-label` string property ("Touch ID" / "system authentication"), and rename `touch-id-*` properties to `biometric-*`.
- Passkeys: `app/src/daemon/browser/dispatch.rs:457` silently returns `Fallback` when `touch_id_available()` is false, so without the polkit action the setting does nothing. The polkit check can serve as the passkey user verification; hide the passkeys toggle when it is unavailable.
- Linux `is_available()`: Vaultkeeper's action is installed (`EnumerateActions`, as Bitwarden does). Also check that it is not misconfigured to `yes`: a non-interactive `CheckAuthorization` must return a challenge, never a free authorization. If not installed, Settings offers "Install system policy" (AppImage only) instead of the option. The lock-screen button additionally requires the in-memory key to be held.
- No agent running (Sway without one): there is no reliable query for this [i]. If an interactive check fails at once without showing a prompt, say "no authentication agent is running" once and hide the option until the next start.
- Label: "Unlock with system authentication". Optionally show a fingerprint icon when fprintd reports an enrolled finger.

## 4. Tray icon

- Slint 1.18's Linux tray is `ksni` and sends **only `icon_pixmap`** (raster ARGB) [v: `i-slint-core-1.18.1/items/system_tray/ksni.rs`]. No icon name, so hosts cannot recolour it.
- Hosts that draw theme icons (Plasma 6, the GNOME AppIndicator extension, Waybar) recolour a `*-symbolic` icon name to the panel's text colour [v: Hex docs; Plasma only with colour-scheme-aware icon themes]. That needs `IconName` + `IconThemePath`, so use `ksni` directly on Linux (it is already a transitive dependency) or add icon-name support to Slint upstream.
- GNOME's top bar stays dark in the light theme [i], so "follow the colour scheme" would put a black icon on a black bar. Sway/Hyprland bars can be any colour.
- Proposal: extend `ThemeChoice` with `Colour`. Linux choices: **Auto** (symbolic name; pixmap fallback = the blue icon, which reads on any bar), **White**, **Black**, **Blue**. Blue may be worth offering on macOS as well.
- No tray host (vanilla GNOME without the extension): detect `org.kde.StatusNotifierWatcher` and `IsStatusNotifierHostRegistered`. If none, `--tray` must not start invisibly: open the vault window and say how to get a tray (or use the hotkey).
- swaybar shows no menus, so left-click (`Activate`) must be useful alone (open the Quick Panel), and every menu action must also exist elsewhere (window, CLI flags).

## 5. Secrets at rest and file permissions

### 5.1 Recommended: seal tokens under the user key, no keyring daemon

The keychain holds only `<user_id>.refresh_token` and `<user_id>.two_factor_remember`. Both are needed only when the user key is in memory: sync, websocket and the probe run only while unlocked, and the 2FA-remember token is used at login after the master password is typed (the cached protected user key can then be decrypted locally).

Shape (mirroring `biometric/envelope.rs`):

- `k = HKDF-SHA256(ikm = user key (64 bytes enc‖mac), salt = SHA-256(user_id), info = "vaultkeeper secrets v1")`, 32 bytes.
- One file per secret, `accounts/<user_id>/<name>.enc`: `"VKS1" ‖ version ‖ nonce[12] ‖ AES-256-GCM(k, nonce, aad = magic‖version‖name‖user_id, token)`. Fresh nonce per write, written with the existing `write_private_atomic` (0600).
- Fits the existing `SecretStore` trait: a `SealedFileStore` that is usable only while a key is provided, with `delete_all_for` deleting the files (logout already wipes the account directory).
- Master-password change: the user key is unchanged, nothing to do. User-key rotation done from another client: the sealed tokens no longer decrypt → treat as logged out and log in again.
- Covers, **for the refresh token**: a stolen disk or backup, other local users. Without the master password the token cannot be read, so nobody can reach the account's API (the vault data is end-to-end encrypted anyway, but the API also allows changing and deleting items). Does not cover a same-uid process while unlocked (it can use the daemon's socket); only the setgid daemon's egid peer check plus per-request confirmation covers that (§5.5).
- **The 2FA-remember token is different.** It only helps someone who already has the master password; that person could also unseal anything derived from the user key. So sealing it under the user key protects nothing. It also does not fit the login order: `session.rs:162-170` reads it before the server login, so the cached protected user key would have to be decrypted first. The only protection that helps here is binding it to this machine (`systemd-creds --user`, §5.2), so a copied disk plus a phished master password cannot skip 2FA. Options: store it as a plain 0600 file (same as a disk copy of today's keychain item minus the keychain password), seal it with `systemd-creds --user` where available, or stop storing it on Linux (the user enters 2FA at each fresh login; unlocks do not need it).

### 5.2 Why not the alternatives

- **Secret Service (gnome-keyring, KWallet, KeePassXC, oo7):** any session-bus client can read an unlocked collection, so it gives the same protection as a 0600 file. It adds a runtime dependency that is often missing on Sway/Hyprland, KDE prompts, and more failure modes. Not worth supporting in v1.
- **`systemd-creds --user`** [v: man page]: systemd ≥ 256, no root and no `tss` group. The key = TPM2 (if present) + root-only `/var/lib/systemd/credential.secret` + uid/username + machine-id, via the root `io.systemd.Credentials` service. Any same-uid process can decrypt. It adds machine binding only: marginal for the refresh token on top of §5.1, but the one thing that protects the 2FA-remember token. Ubuntu 24.04 lacks it.
- **Plain 0600 files without encryption:** readable from any backup or copied home directory.

### 5.3 TPM 2.0 verdict

- Good for: (1) machine binding through `systemd-creds --user` (see above); (2) later, a **PIN unlock that survives restart**: seal the user key in a TPM object with `authValue` = PIN and `PolicyAuthValue`. The TPM's dictionary-attack lockout makes a short PIN safe. This is the only Linux mechanism close to Touch ID's "key at rest, user-verified, hardware-rate-limited".
- Costs: direct `/dev/tpmrm0` access usually needs the `tss` group (a root action); `tss-esapi` pulls in C libraries; DA lockout is TPM-global.
- **Emulated TPM (swtpm):** its state is an ordinary file, so it protects nothing. Without a hardware TPM, `systemd-creds` already falls back to the root-only host key. Use swtpm only to test TPM code paths in CI.
- Not in v1. Keep the quick-unlock abstraction (like `envelope::KeyAgreement`) so a `TpmPinSealer` can be added later.

### 5.4 Startup permission checks (daemon and UI)

- First thing: `umask(0o077)`, `prctl(PR_SET_DUMPABLE, 0)` (Linux counterpart of `PT_DENY_ATTACH`), `RLIMIT_CORE=0` (exists).
- Data dir `$XDG_DATA_HOME/vaultkeeper` (`~/.local/share/vaultkeeper`) and config dir: owned by euid, 0700, not a symlink. Open with `O_NOFOLLOW | O_DIRECTORY`, `fstat`, then work through `openat` on that fd (no TOCTOU). Files: regular, owner euid, 0600. Reject non-trivial POSIX ACLs (`system.posix_acl_access` / `_default`).
- Sockets in `$XDG_RUNTIME_DIR/vaultkeeper` (0700). Refuse to start if `$XDG_RUNTIME_DIR` is unset or not 0700/ours; never fall back to `/tmp`.
- On violation: **repair** mode bits when owner and type are right (restored backup, old umask); **refuse** with an exact message on wrong owner, a symlink in the path, ACLs, or a bad runtime dir; **warn** for things that are not ours (home dir wider than 0750).
- `crates/platform/src/fs.rs` already does 0700/0600 and atomic writes; the new parts are ownership, symlink, ACL and runtime-dir checks.

### 5.5 Persistent quick unlock: setgid daemon

The question: can the user key sit on disk, encrypted, so that only Vaultkeeper (not another process of the same user) can decrypt it, as the code-signature ACL and Secure Enclave allow on macOS?

What does not work against an unconfined same-uid process:

| Mechanism | Why not |
|---|---|
| AppArmor | Confines only profiled processes; everything else runs unconfined. Denying others needs a whole-system policy, not something an app can ship. |
| SELinux private type | On Fedora targeted policy, `unconfined_t` may ptrace every domain (`deny_ptrace` boolean, default off) and transitions with `noatsecure`, so `LD_PRELOAD` survives entry into `vaultkeeper_t` [f]. Works only for Fedora "confined users"; Ubuntu/Debian/Arch have no SELinux. |
| Landlock, seccomp | Restrict only the calling process and its children. |
| Yama, `PR_SET_DUMPABLE`, memfd_secret | Memory only. An attacker can fork, `PTRACE_TRACEME` and exec the real binary, controlling it from the first instruction. |
| Flatpak/Snap, Secret portal, oo7 | The sandbox restricts the app, not host processes; the portal's per-app key lives in the login keyring. GNOME: "isolating unsandboxed apps is simply impossible" [f]. |
| Kernel keyrings, trusted/encrypted keys | Not persistent; `@u` is reachable by every same-uid process. |
| TPM2 sealing | Policies know boot state, never the calling process; IMA PCR 10 grows with every exec. `/dev/tpmrm0` is `root:tss` [f]. |
| systemd-creds, Secret Service, KWallet, pam_gnome_keyring, fscrypt | Unlocked for the whole uid; KWallet's per-app ACL trusts a client-supplied name. |
| Broker as a separate system user | `/proc/<pid>/exe` and TracerPid checks are racy and spoofable by pre-exec ptrace; it is sound only if it checks the peer's egid, which needs the setgid binary anyway. |

Peers: Bitwarden, KeePassXC 2.8 and 1Password keep quick unlock in memory only and ask for the master password after a restart [f]. A persistent mode would put Vaultkeeper ahead of them.

What works: a daemon installed setgid to a dedicated group. Kernel facts it rests on [f: ld.so(8), execve(2)]:

- Exec of a setgid binary sets `AT_SECURE`: ld.so ignores `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`.
- The process becomes non-dumpable (`fs.suid_dumpable` = 0, Ubuntu 2): same-uid ptrace and `/proc/<pid>/{mem,maps,environ,fd}` need `CAP_SYS_PTRACE`, regardless of Yama or LSM.
- An exec that is being traced or runs under `no_new_privs` does not get the group, so a pre-traced copy cannot read the key.
- Precedent: OpenSSH installs `ssh-agent` setgid "to avoid ptrace(2) attacks"; `unix_chkpwd` is setgid `shadow`.

Shape:

- Split a headless `vaultkeeper-daemon` (pure Rust, no GUI or GPU libraries) installed `root:vaultkeeper 2755` under `/usr/libexec`. It takes paths from `getpwuid`, never from the environment or arguments, and runs as a systemd user service so no attacker process is its ancestor.
- The UI stays unprivileged: the daemon spawns it with a clean environment and an inherited socketpair, and the UI calls `PR_SET_DUMPABLE(0)` before it shows any vault data.
- Key at rest: user key sealed under `HKDF(group_half ‖ home_half)` with the AES-GCM file format of §5.1. `group_half` lives in `/var/lib/vaultkeeper/<uid>/` (tmpfiles.d `1770 root vaultkeeper`, group from sysusers.d); `home_half` is a 0600 file in `$XDG_DATA_HOME`. A home backup alone leaks nothing; another user's daemon lacks the home half.
- Release only after the polkit check (§3.2). The daemon opens the `group_half` fd, then drops the group.
- IPC peer check: `SO_PEERCRED` egid == `vaultkeeper`. With the setgid binary this is a real boundary, not only the mistake guard of §7.6.
- Guards: refuse persistent mode when `getegid()` lacks the group (AppImage on a `nosuid` FUSE mount, `no_new_privs`, traced exec) and fall back to the in-memory mode of §3.3; set `PR_SET_DUMPABLE(0)` explicitly in case `suid_dumpable` = 1.
- **Per-request confirmation.** The group proves the genuine binary sent a request, not that the user asked for it: malware can run `vaultkeeper get` itself, and parent pid, TTY and session are all attacker-chosen. CLI reveals, SSH agent signatures and browser fills need their own polkit confirmation. An optional "trust for N minutes" window is a convenience, not a boundary. macOS has the same property for a signed CLI.
- Later: a udev rule giving group `vaultkeeper` an ACL on `/dev/tpmrm0` allows TPM + PIN sealing of `group_half` (§5.3) without the `tss` group; the package already needs root for setgid.

Covers: other same-uid processes reading the key at rest or in memory, `LD_PRELOAD` and pre-exec ptrace, stolen disks and backups. Does not cover: root, the kernel, `SIGSTOP`/`SIGKILL` of the daemon (denial of service), argv/config/input bugs in the daemon (they become a security boundary), or AppImage installs. Trust moves from Secure Enclave hardware to kernel-enforced process integrity.

### 5.6 Later: BPF LSM hardened mode

A root system service could load BPF LSM programs at boot that allow `file_open` on the key and data dir only for Vaultkeeper's executable (by inode, or by fs-verity digest checked with `bpf_verify_pkcs7_signature`: a code-signature equivalent), deny `ptrace_access_check` (covers `/proc/<pid>/mem`, `process_vm_*`, `pidfd_getfd`), exec while traced and `task_kill` against Vaultkeeper, and gate `unix_stream_connect` to the daemon socket.

| Distro | `bpf` in the default active LSM list? |
|---|---|
| Fedora | Yes [f] |
| Arch | Yes [f] |
| Ubuntu 24.04 and 26.04 | No: `CONFIG_BPF_LSM=y`, but `bpf` is missing from `CONFIG_LSM`; it needs `lsm=…,bpf` on the kernel command line and a reboot [f] |

kfuncs: `bpf_verify_pkcs7_signature` since 6.1, `bpf_get_fsverity_digest` since 6.8 [f]. Secure Boot lockdown can refuse some BPF loads. fs-verity must be re-enabled after each package upgrade, so prefer a signed digest allow-list over inode pinning. A bug in a system-wide `file_open` hook can lock users out of their files, so the programs must fail open except for Vaultkeeper's paths. IPE (6.12+) is whole-system code integrity, not a per-app gate.

Adds over §5.5: identity by content, signal denial, and protection of the whole data dir. Does not fix the per-request confirmation need. Cost ≈ 4–6 weeks against ≈ 1 week for setgid. Verdict: optional "hardened mode" package later, enabled only where `bpf` appears in `/sys/kernel/security/lsm`.

## 6. Quick Panel window on Wayland

- **Focus (biggest UX risk).** The daemon spawns the UI process; Wayland gives focus only with an xdg-activation token. Without one, GNOME shows "Vaultkeeper is ready" instead of focusing. Pass a token to the UI process in `XDG_ACTIVATION_TOKEN`; winit reads it on window creation. Token sources: the GlobalShortcuts `Activated` signal (newer portal versions [i]), the compositor's `exec` environment [i], KDE's SNI `ProvideXdgActivationToken` [i]. Verify on every desktop.
- **Placement:** clients cannot position windows. Use a stable app id, a fixed size (min = max, so tiling compositors float it, as Hex does), and document window rules for Sway/Hyprland. Layer-shell would give a real overlay but winit/Slint do not support it.
- "Hide on focus loss" works (winit focus events). There is no Dock icon issue on Linux.

## 7. Other platform pieces

### 7.1 Global shortcuts

GlobalShortcuts portal via `ashpd` (GNOME 48+, KDE, Hyprland). The portal identifies an unsandboxed app by its `.desktop` file/app id [i: Hex writes a minimal `.desktop` for this reason]. Fallbacks: GNOME 46 → write a custom keybinding (`org.gnome.settings-daemon.plugins.media-keys`) running `vaultkeeper --quick`; Sway → document `bindsym`. Settings should show what the desktop actually granted.

### 7.2 Lock, sleep, network

Subscribe to `org.gnome.ScreenSaver` and `org.freedesktop.ScreenSaver` `ActiveChanged` (what Bitwarden does), plus logind `Session.Lock`, the `LockedHint` property and `Manager.PrepareForSleep`, which covers Sway/Hyprland when the locker is started through `loginctl lock-session` (standard swayidle/hypridle configs). Network: NetworkManager `StateChanged` or simply the existing probe.

### 7.3 Clipboard

The daemon owns the clipboard (`crates/ipc/src/clipboard.rs`: it outlives every UI process and runs the auto-clear). A windowless Wayland client can set or clear the selection only with data-control (`ext-data-control-v1` or `wlr-data-control`). `wl-clipboard-rs` 0.9.5 (already pulled by arboard) supports both [v]. Offer `text/plain;charset=utf-8` plus `x-kde-passwordManagerHint: secret`; arboard does not set the hint on Linux [v], so use `wl-clipboard-rs` directly. Without data-control (GNOME ≤ 48): copy from the focused UI process instead, and auto-clear is not guaranteed. Bitwarden's workaround is the RemoteDesktop portal clipboard (consent dialog plus a remote-control indicator).

### 7.4 Auto-type

GNOME/KDE: RemoteDesktop portal with a persisted restore token, so consent is asked once; GNOME shows its remote-control indicator while the session is open. Sway/Hyprland: `zwp_virtual_keyboard_v1` with a generated keymap (how `wtype` types any Unicode character). Target handling is weaker than macOS: you cannot reactivate "the previous app" except through wlroots foreign-toplevel on Sway/Hyprland, so close the Quick Panel, let the compositor return focus, then type. Watch held modifiers: the user's still-held hotkey modifiers merge into injected keys (Hex waits for release plus 250 ms). Highest-risk area.

### 7.5 Autostart

GNOME/KDE: Background portal `RequestBackground(autostart=true)`, or `~/.config/autostart/<appid>.desktop`. Sway: `exec vaultkeeper --tray`; Hyprland: `exec-once = vaultkeeper --tray` (uwsm users get XDG autostart).

### 7.6 IPC peer check

There are no code signatures, and the macOS guarantee does not carry over: a same-uid attacker can start the real binary with `LD_PRELOAD`, or ptrace it before `PR_SET_DUMPABLE` runs, so the peer check is a guard against mistakes and stray clients. The exception is the setgid daemon of §5.5, where the peer's egid is a real boundary. Keep it cheap and correct: uid == own uid; `SO_PEERPIDFD` when available; compare `/proc/<pid>/exe` (st_dev, st_ino) with `/proc/self/exe`; re-check before sensitive operations (reveal, CLI `get`). One multi-call binary keeps it to a single identity. The same applies to the SSH agent's peer info (vendored code currently has macOS-only branches).

### 7.7 Browser native messaging

Manifests in `~/.config/google-chrome/NativeMessagingHosts`, `~/.config/chromium/…`, `~/.config/BraveSoftware/Brave-Browser/…` and `~/.mozilla/native-messaging-hosts`. Risk: Ubuntu's default Firefox is a Snap, and Snap and Flatpak browsers cannot simply spawn a host binary [i]. Check the WebExtensions/native-messaging portal state before promising Firefox on Ubuntu.

### 7.8 Packaging and updates

.deb, .rpm and AUR (they can also ship the polkit policy, `.desktop` file and symbolic icon), plus AppImage. Flatpak does not fit: the SSH agent socket, the native-messaging host, the polkit policy and auto-type all fight the sandbox. The updater checks a code signature on macOS; on Linux, sign release artifacts with an Ed25519 (minisign-style) key embedded in the binary, self-update only AppImage/user-local installs, and leave package installs to the package manager.

### 7.9 Sway and Hyprland setup to document

Everything below needs a fixed **app id** (decision): the same string names the `.desktop` file the portal uses, the Wayland `app_id` of the windows, the portal shortcut ids (`<appid>:quick`) and the tray icon (`<appid>-symbolic`). Suggestion: `io.github.avbel.Vaultkeeper`. Whether Slint lets the app set the Wayland `app_id` needs checking [i].

Sway:

```
exec vaultkeeper --tray
bindsym $mod+Shift+space exec vaultkeeper --quick
for_window [app_id="io.github.avbel.Vaultkeeper"] floating enable
exec swayidle -w timeout 300 'loginctl lock-session' lock 'swaylock -f' before-sleep 'loginctl lock-session'
exec /usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1   # any polkit agent; quick unlock needs one
```

Hyprland (syntax changes between releases; 0.56+ also has Lua-style `hl.bind(...)` [v: Hex docs]; window-rule syntax has changed several times [i]):

```
exec-once = vaultkeeper --tray
bind = SUPER SHIFT, space, global, io.github.avbel.Vaultkeeper:quick   # or: exec, vaultkeeper --quick
windowrule = float, class:^(io\.github\.avbel\.Vaultkeeper)$
# hypridle.conf: lock_cmd = pidof hyprlock || hyprlock ; before_sleep_cmd = loginctl lock-session
```

Both: Waybar instead of swaybar if you want the tray menu; `SSH_AUTH_SOCK` pointing at Vaultkeeper's agent socket.

### 7.10 Smaller items

- Paths: `directories` already gives XDG paths; `paths.rs` comment needs a Linux line.
- Slint: build winit without X11; `rfd` needs its `xdg-portal` feature for file dialogs on Linux.
- `fs::swap` (used by the macOS updater) is macOS-only; Linux has `renameat2(RENAME_EXCHANGE)` if needed.
- Re-measure memory: D-Bus and Wayland connections change the tray-only footprint.

## 8. Open risks to check on real machines

1. xdg-activation token flow for the Quick Panel on GNOME, KDE, Sway and Hyprland.
2. GNOME 49 ext-data-control (do unprivileged clients get it?) and what GNOME 46 does when the clipboard owner exits.
3. GNOME top-bar colour in the light theme; how the AppIndicator extension renders symbolic names.
4. Portal app-id detection for a non-Flatpak binary (`.desktop` file plus a correctly named systemd scope).
5. Polkit behaviour with no agent running (fail-fast vs hang) on Sway, and whether `polkit-1` uses pam_fprintd on Ubuntu, Fedora and Arch once fingerprint login is enabled.
6. Firefox Snap native messaging on Ubuntu.
7. GNOME version that first ships the GlobalShortcuts portal (46 confirmed missing).

Open decisions:

1. Support floor: include GNOME 46 / Ubuntu 24.04 (with fallbacks and no guaranteed clipboard clear), or start at GNOME 48/49.
2. The app id.
3. The 2FA-remember token on Linux: plain 0600 file, `systemd-creds --user` where available, or not stored.
4. Default tray icon on Linux: Auto (symbolic name, blue pixmap fallback) or Blue.
5. Persistent quick unlock through the setgid daemon (§5.5) in v1, or later; and the default "trust for N minutes" window for CLI reveals.

Decided: quick unlock through polkit (PAM), §3.2.

## 9. Effort estimate (one developer, rough)

| Block | Weeks |
|---|---|
| Platform traits, no behaviour change (README phase 1) | 1–2 |
| Linux bring-up: build, CI, XDG paths, sockets, hardening, permission checks | 1–1.5 |
| Tray via ksni, icon choices, no-host detection | 1 |
| Hotkeys: portal + GNOME 46 fallback + activation tokens | 1–1.5 |
| Clipboard via data-control + concealment | 0.5–1 |
| Lock/sleep via logind + ScreenSaver | 0.5 |
| Sealed token store (replaces keychain) | 0.5–1 |
| **MVP total** (vault, Quick Panel, tray, clipboard, SSH, CLI; packages; no auto-type, quick unlock, updater) | **6–8** |
| Polkit quick unlock (policy file, AppImage `pkexec` install) + UI relabel/hiding | 1–1.5 |
| Setgid daemon persistent mode (split daemon, group key half, per-request confirmation) | 1–1.5 |
| Auto-type (portal + virtual keyboard) | 2–3 |
| Browser native messaging (incl. Snap/Flatpak checks) | 1 |
| Signed self-updater for AppImage | 1–1.5 |
| Test matrix on 4 desktops + fixes | 2 |
| **Parity total** | **15–19.5** |

## Sources

- Code: `crates/platform/src/{biometric.rs,keychain.rs,fs.rs,hardening.rs}`, `crates/vault/src/{secrets.rs,vault/sync.rs,vault/background.rs}`, `crates/ipc/src/{peer.rs,clipboard.rs}`, `app/ui/*.slint`, `app/src/daemon/browser/dispatch.rs`, `i-slint-core-1.18.1/items/system_tray/ksni.rs`, `arboard-3.7.0`, `wl-clipboard-rs-0.9.5`, `global-hotkey-0.9.0`.
- Bitwarden desktop_native (local `../clients`): `biometric/src/linux.rs`, `core/src/process_isolation/linux.rs`, `core/src/clipboard/portal_backend.rs`, `core/src/powermonitor/linux.rs`, `resources/com.bitwarden.desktop.policy`.
- fprintd polkit policy: gitlab.freedesktop.org/libfprint/fprintd `data/net.reactivated.fprint.device.policy.in`.
- systemd-creds(1) (systemd 262) and ArchWiki systemd-creds.
- ArchWiki XDG Desktop Portal (backend/interface table).
- Hex Linux docs (github.com/anomalyco/hex `docs/linux.md`): tray icon recolouring, portal shortcuts per desktop, wtype vs RemoteDesktop paste, GNOME 46 limits.
- sway PRs for tray dbusmenu (#6249, #8405, #8698, #8920: open).
- KeePassXC 2.8.0 (Oct 2026): polkit quick unlock and portal auto-type on Linux.
- cliphist issue #58, arboard issue #129 (`x-kde-passwordManagerHint`).
- Security design review (Fable), §3, §5, §7.6.
- Fable second opinion on key-at-rest isolation (2026-11-14), §5.5–5.6: ld.so(8) and execve(2) secure-execution rules; OpenSSH release notes (setgid ssh-agent); fedoraproject.org/wiki/Features/SELinuxDenyPtrace; blog.ce9e.org/posts/2024-07-27-password-plan; support.1password.com/system-authentication-linux-security; systemd `rules.d/70-uaccess.rules.in`; LSM lists from discussion.fedoraproject.org (#117248), bbs.archlinux.org (#313863), github.com/actions/runner-images #14783; docs.kernel.org/security/ipe.html; tetragon.io installation FAQ; KubeArmor support matrix.
