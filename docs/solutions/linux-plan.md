# Linux support (Ubuntu 26.10, Fedora 45, Arch as Omarchy 4.5; Wayland only; GNOME 51, KDE Plasma 6.7/6.8, Sway 1.12, Hyprland 0.56/0.57)
Design sources: docs/solutions/linux-support.md (design §), docs/solutions/linux-gaps.md (gaps §, and its "Decisions" of 2026-11-20), docs/solutions/linux-ideas.md (ideas §; §1 floor, §7 Homebrew, §8 updates, §9 baseline, §10 hotkeys, §11 chains, §12 BPF). User decisions: latest Ubuntu and Fedora, plus Arch **only as the Omarchy build** (its defaults are the supported Arch configuration; plain Arch runs only when the security probes pass), Wayland only, four desktops at the versions those ship; Homebrew tap first, deb/rpm later, no AppImage; auto-update hidden under a package manager; every protection a fallback chain, strongest first; BPF LSM now as the first link, identity by a release-signed fs-verity digest, one-time privileged helper; refuse to start when a required chain has no link unless `--skip-security-issues`; hotkeys and labels as on Windows.
Conventions for every step:
- No behaviour change on macOS or Windows. Every step that touches shared code runs the macOS checks of the crates it touched; Windows code paths stay under `cfg(windows)`.
- Linux code lives in `#[cfg(target_os = "linux")]` modules (`linux.rs` or a `linux/` dir). Portable parts (chain model, desktop-file and unit templates, trigger conversion, install-kind logic, manifest JSON, refusal tables) are plain functions over injected inputs and unit-tested on macOS.
- Three-way rule for text and chords: macOS is the odd one out (`cfg!(target_os = "macos")`); Linux takes the Windows branch for chords/labels; Windows-only *features* keep `cfg!(windows)` (ideas §10).
- Every protection is a `vk_platform::security::Chain` (step 1a); a new mechanism is a new link with a probe, never an ad-hoc `if`. The BPF links share one probe (4c).
- Linux check from this Mac: `scripts/check-linux.sh [cargo args]` (Docker `rust:1.99.1-bookworm`, step 0b). Linux tests run in CI (0c) and in the VMs; the Docker check is clippy + `cargo test` of portable crates.
- Crates already chosen: ashpd 0.14.1 (portals), wl-clipboard-rs 0.9.5, landlock 0.4.7, zbus 5.19 (already in the tree; 6.x only if ashpd needs it), ksni 0.3.7, libbpf-rs/libbpf-cargo 0.27.2, rustix 1.1 + hand-written constants for `SO_PEERPIDFD` (77), `SO_PASSPIDFD` (76), `PIDFD_GET_INFO` (`_IOWR(0xFF, 11, pidfd_info)`), `PR_SET_MDWE` (65) — libc 0.2.191 lacks them [v]. No new crate without a `deps:` line.
- Port from GPL sources before writing from scratch, naming the file in a comment: Bitwarden `desktop_native/core/src/process_isolation/linux.rs` (dumpable/RLIMIT), `clipboard/portal_backend.rs` (RemoteDesktop + Clipboard portal), `ipc/mod.rs` (manifest dirs); kernel selftests `tools/testing/selftests/bpf/progs/test_sig_in_xattr.c` and the LSM selftests for the BPF programs.
- Every `unsafe` block gets a `// SAFETY:` comment; comments explain why. Workspace clippy is pedantic with `-D warnings`; `unwrap` is denied.
- Phase gate (orchestrator, before every phase commit): `scripts/check.sh && CARGO_TARGET_DIR=target/lean cargo test --workspace` on macOS, `scripts/check-linux.sh --workspace --all-targets`, and a green `linux` CI job. From phase 3 on, the phase's section of docs/solutions/linux-test-checklist.md (7a) is run by the user in the VMs; a step marked `gate:` must not be built on until the user reports the result.
- README.md changes only with the user's approval (7b proposes the text). Vendored changes are recorded in vendor/PATCHES.md. No new git branch and no commit without the user's word (repo rules); the orchestrator proposes a `linux-support` branch from main when the user says so.
- No distribution default is assumed anywhere in code: the chain probes (1a/1b) decide on every distribution, refusal and warning texts name the missing item and the fix for the detected distribution (`/etc/os-release` `ID`, Omarchy marked by the `omarchy` package), and docs/solutions/linux-requirements.md (7d) documents what the probes need. On Arch this is the whole support story.
- Verification VMs (each driven through its MCP): `vm-fedora-gnome` = Fedora 45 Workstation, GNOME 51, UEFI with Secure Boot; `vm-kubuntu` = Kubuntu 26.10, Plasma 6.7.5, plus an optional `apt install sway` session; `vm-fedora-sway` = Fedora 45 Sway Spin (sway-config-fedora: Waybar, swaylock/swayidle, lxqt-policykit, SDDM); `vm-omarchy` = Omarchy v4.5.0 (Arch, `linux-omarchy` 7.2.15, Hyprland 0.57.2, Omarchy shell as tray + polkit agent, UWSM, Limine UKI, btrfs + LUKS, Secure Boot off, Chrome). A `verify: vm` line names the VMs; the appendix maps every manual check to them. Untested under this set: Ubuntu GNOME and Fedora KDE; a GNOME session on `vm-kubuntu` (`sudo apt install ubuntu-desktop-minimal`, log in to "Ubuntu") covers Ubuntu GNOME (AppIndicator on by default, snap Firefox) cheaply [i]; Fedora KDE stays untested. Hyprland: `vm-omarchy` is the reference; Ubuntu 26.10 Hyprland (universe) stays supported without a VM; Fedora Hyprland is unsupported.
- Status conventions as in .plan/windows-support.md: `done-when`, `needs`, `difficulty`, `kind`, plus `effort` in person-days and `verify` (how: `unit` = cargo test on macOS, `docker` = scripts/check-linux.sh, `ci` = linux job, `vm` = manual on Ubuntu 26.10 / Fedora 45 per desktop).

## Phases at a glance
| Phase | Steps | Goal | Effort (pd) |
|---|---|---|---|
| 0 Build, CI, sealed store | 0a–0d | Linux compiles, Docker check, `linux` CI job, SealedFileStore on Linux | 2 |
| 1 Security framework and gate | 1a–1f | chain model, vk-linux probes, `--skip-security-issues` gate, hardening, secure memory, Landlock | 9 |
| 2 Storage, sockets, identity, upgrades | 2a–2f | permission checks, runtime-dir sockets, pidfd peer identity, inherited UI channel, upgrade state, systemd-creds | 6.5 |
| 3 Desktop integration | 3a–3l | app id, hotkeys, focus, clipboard, tray, lock/sleep, autostart, links/dialogs/network, auto-type, quick unlock, texts, Security settings | 20 |
| 4 BPF LSM | 4a–4d | VM spike, root helper + D-Bus service, chain links and enrol flow, signed fs-verity digest in releases | 9.5 |
| 5 Browser | 5a–5d | manifests + proxy, parent identity, status/socket/tests, passkeys | 4.5 |
| 6 Packaging | 6a–6c | Linux tarballs, Homebrew formula + tap bump, install-kind and updater hiding | 3 |
| 7–8 Docs, review, PR | 7a–7d, 8a | checklist, docs, requirements list, review, PR | 3.5 |
| 9 later | 9a | .deb and .rpm | 2 |

## 0a Fix the three Linux compile errors
files: app/src/os/mod.rs, app/src/daemon/update/install_unavailable.rs, crates/platform/src/autostart.rs
do: - `dock` and `placement` (app/src/os/mod.rs:68, :87) get a `cfg(target_os = "linux")` arm returning the existing no-op implementations (`NoDock`, `NoPlacement`, as Windows's dock does); the compositor owns placement on Wayland (design §6), so these stay no-ops for good.
  - `install_unavailable::Installer` gains `zip_path(&self) -> PathBuf` with the macOS signature (`match self.0 {}`), so `download_and_stage` (update/mod.rs:292) compiles; the Linux updater stays "unavailable" (updates come from Homebrew, ideas §8).
  - `TRAY_ARG` in autostart.rs:15 is gated `cfg(any(target_os = "macos", windows))` until step 3g uses it on Linux.
done-when: `docker run … rust:1.99.1-bookworm cargo check --workspace --all-targets --locked` passes (the exact command of gaps §1, until 0b exists); `cargo clippy -p vaultkeeper -p vk-platform --all-targets -- -D warnings`
difficulty: easy
effort: 0.5
verify: docker
kind: change

## 0b Linux cross-check script and target flags
files: scripts/check-linux.sh, .cargo/config.toml
do: - `scripts/check-linux.sh [cargo args]`: POSIX sh, `set -e`; runs `docker run --rm -v "$PWD":/src -w /src -v vaultkeeper-linux-cargo:/usr/local/cargo/registry -v vaultkeeper-linux-target:/src/target-linux -e CARGO_TARGET_DIR=/src/target-linux rust:1.99.1-bookworm sh -c 'apt-get -qq update && apt-get -qq install -y libfontconfig1-dev libxkbcommon-dev libwayland-dev libdbus-1-dev libudev-dev clang libelf-dev zlib1g-dev bpftool >/dev/null && cargo clippy --locked "$@" -- -D warnings'`; a `--test` flag switches clippy for `cargo test`. Clear message if Docker is missing. Image tag pinned; arm64 host runs the arm64 image, which is fine for a check.
  - `.cargo/config.toml`: `[target.x86_64-unknown-linux-gnu]` and `[target.aarch64-unknown-linux-gnu]` rustflags `-C relro-level=full`, `-C link-arg=-Wl,-z,now`, `-C link-arg=-Wl,-z,noexecstack`; nothing for other targets (the Windows block stays).
done-when: `sh -n scripts/check-linux.sh`; `scripts/check-linux.sh --workspace --all-targets`
needs: 0a
difficulty: easy
effort: 0.5
verify: docker
kind: change

## 0c CI job for Linux
files: .github/workflows/ci.yml, .github/workflows/cargo-cache.yml
do: - Job `linux` (ubuntu-latest): apt deps as in 0b, `rustup show active-toolchain || rustup toolchain install`, Swatinem/rust-cache@v2 `shared-key: linux-ci`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked`. Tests that need a Wayland session or a session bus get `#[cfg_attr(target_os = "linux", ignore = "needs a Wayland session")]` with that reason; tests that need Landlock ABI ≥ 8 or kernel ≥ 6.13 skip at run time with a logged reason (the runner kernel is 6.8 [v: ubuntu-latest image]).
  - Job `linux-arm` (ubuntu-24.04-arm): clippy only, to catch `aarch64` cfg mistakes cheaply.
  - `cargo-cache.yml`: job `linux-deps` cooking release dependencies for `-p vaultkeeper --target x86_64-unknown-linux-gnu`, shared key `linux-release`, mirroring the macOS job.
done-when: `ruby -ryaml -e 'YAML.load_file(".github/workflows/ci.yml"); YAML.load_file(".github/workflows/cargo-cache.yml")'`; jobs `linux` and `linux-arm` exist; a green run on the branch
needs: 0b
difficulty: easy
effort: 0.5
verify: ci
kind: change

## 0d SealedFileStore wired into the Linux daemon
files: app/src/daemon/secrets.rs, app/src/daemon/mod.rs, crates/vault/src/sealed_store.rs
do: `app/src/daemon/secrets.rs:70` picks `SealedFileStore` (Windows plan 1l/1m/1p, on main since 64501c3) on `target_os = "linux"` with `vk_platform::fs::write_private_atomic` and **no** `BlobWrapper` yet (2f adds systemd-creds for the 2FA-remember token); macOS keeps `KeychainStore`, Windows keeps DPAPI. The store constructor stays portable so the macOS test suite exercises the Linux configuration (`#[cfg(test)]` builds it explicitly).
done-when: `cargo test -p vaultkeeper secrets`; `scripts/check-linux.sh -p vaultkeeper --all-targets`; the login → lock → unlock → sync lifecycle test (`crates/vault/tests/sealed_lifecycle.rs`) passes in the `linux` CI job
needs: 0c
difficulty: easy
effort: 0.5
verify: unit, ci
kind: change

## 1a Security chain framework (portable)
files: crates/platform/src/security.rs, crates/platform/src/security/, crates/platform/src/lib.rs
do: - `security::{Chain, Link, Probe, ChainStatus, Required, Strength, Report}` as in ideas §11: links ordered strongest first, `stacks: bool`, probe and activate closures over an `Env` (uid, dirs, env vars, injected syscall shims), evaluation activates the strongest exclusive link plus every available stacking link, status `Full | Standard | Reduced | Off`, `Report::refusals()` (chains with `Required::Refuse` and no link), `Report::warnings()` (below `minimum`), `Report::fingerprint()` (stable hash of refusal ids, for `security accept`).
  - `Report::table()` renders the CLI/UI table (chain, status, active link, note, fix); `serde` for the log and for IPC.
  - Chains on macOS and Windows are registered but empty except where today's hardening already fits (RLIMIT_CORE, DACL): no behaviour change, the table simply shows them.
done-when: `cargo test -p vk-platform security` with fake probes covering: strongest link wins, stacking links all activate, minimum → Reduced, no link → refusal only for Refuse chains, fingerprint stable under reordering; `cargo clippy -p vk-platform --all-targets -- -D warnings`
difficulty: medium
effort: 1
verify: unit
kind: change

## 1b vk-linux crate: constants and probes
files: crates/linux/, Cargo.toml
do: - New workspace member `crates/linux`, package `vk-linux`, "Linux kernel and desktop probes shared by vk-platform, vk-ipc and the app". Compiles everywhere; real code under `cfg(target_os = "linux")`, portable parsers (kernel version, `/proc/sys` values, `lsm` list, `XDG_*` env) tested on macOS.
  - Constants missing from libc 0.2.191: `SO_PEERPIDFD`, `SO_PASSPIDFD`, `PIDFD_GET_INFO`, `struct pidfd_info` (v7.3 layout with `mask`, `cgroupid`, pid/tgid/ppid, uids/gids, `exit_code`, coredump fields, `supported_mask`), `PIDFD_INFO_*` masks, `PR_SET_MDWE`, `PR_MDWE_REFUSE_EXEC_GAIN`, `PR_MDWE_NO_INHERIT`, `MFD_*`/`memfd_secret` syscall numbers per arch, `mseal`, `landlock_*` syscall numbers, `LANDLOCK_CREATE_RULESET_VERSION`.
  - `distro::detect() -> Distro { Ubuntu, Fedora, Omarchy, OtherArch, Other }` from `/etc/os-release` (`ID`, `ID_LIKE`) plus the Omarchy marker (`/usr/share/omarchy` or `pacman -Q omarchy`), used only to pick the fix text of a failed probe, never to skip a probe.
  - Probes (each returns `Probe` from 1a): kernel version ≥ 6.5/6.13; `SO_PEERPIDFD` on a `socketpair`; `memfd_secret` create+close; `mseal` on a private page; MDWE set+query; dumpable get/set; Landlock ABI; Yama scope; `/sys/kernel/security/lsm` contains `bpf`; Wayland (`WAYLAND_DISPLAY` and a connect to `$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY`); runtime dir (`statx` owner/mode, `statfs` `TMPFS_MAGIC`); data dir and files (owner, symlink, modes); systemd user manager (`$XDG_RUNTIME_DIR/systemd/notify` exists); D-Bus names (`org.freedesktop.portal.Desktop`, `org.freedesktop.Notifications`, `org.kde.StatusNotifierWatcher`, `org.freedesktop.login1` on the system bus) through zbus `NameHasOwner` with a 2 s timeout, run once and cached.
done-when: `cargo test -p vk-linux` (parsers on macOS; os-release fixtures for Ubuntu, Fedora, Omarchy, plain Arch); `scripts/check-linux.sh -p vk-linux --all-targets --test` (probe tests run in Docker: kernel and socket probes pass, desktop probes report Unavailable with a reason, never panic)
deps: rustix@1.1 (present), zbus (present)
needs: 1a
difficulty: medium
effort: 2
verify: unit, docker, ci
kind: change

## 1c Baseline gate, `--skip-security-issues`, `vaultkeeper security …`
files: app/src/cli.rs, app/src/daemon/mod.rs, app/src/ui_process/mod.rs, app/src/os/security_gate.rs, app/src/daemon/launcher.rs, app/src/settings.rs, app/ui/refusal.slint
do: - `cli.rs` parses `--skip-security-issues` for every role and the subcommand `security` with `status | requirements | accept [ids…] | install | enroll | verify | uninstall` (install/enroll/verify/uninstall forward to the helper, 4c; `requirements` prints the table of ideas §9.1 with the fix column for the detected distribution).
  - Every refusal/warning line is `<item>: <what the probe saw> — <fix>`; the fix comes from a per-item table keyed by `Distro` (apt / dnf / pacman and Omarchy commands such as `omarchy-refresh-limine`) with a generic fallback for `Other`. Portable, unit-tested text.
  - `security_gate::enforce(role, skip) -> anyhow::Result<Report>` runs after `startup_check::enforce` in `daemon::run` (mod.rs:86) and `ui_process::run` (mod.rs:47) and before the CLI connects; the CLI role probes only kernel, runtime dir and data dir. A refusal with `skip` or with an accepted set covering it continues with the warning badge; otherwise: CLI prints `Report::table()` and exits 78; the daemon spawns `vaultkeeper --ui --refusal <path>` (the UI renders the table with "Quit" and "Start anyway (not recommended)", which re-launches the daemon with the flag) and posts an `org.freedesktop.Notifications` notification; if the UI cannot start, the report goes to `$XDG_STATE_HOME/vaultkeeper/last-refusal.txt`.
  - The daemon appends `--skip-security-issues` to the UI child's argv when it was started with it (launcher.rs); autostart entries, the user unit and the desktop file never carry it.
  - `security accept` stores `security_accepted: Option<{ fingerprint, issues }>` in settings.json; a later start whose refusal ids ⊆ accepted proceeds; new ids refuse again. `security status` prints the table (from the running daemon over IPC when it runs, else recomputed).
  - macOS/Windows: `enforce` evaluates the (mostly empty) chains and never refuses — no behaviour change.
done-when: `cargo test -p vaultkeeper security_gate` covers: refusal table, accept subset/superset, fingerprint, flag propagation to the UI argv (launcher test), exit code; `scripts/check-linux.sh -p vaultkeeper --all-targets`
needs: 1a, 1b
difficulty: hard
effort: 2
verify: unit, docker, vm (the refusal window and the per-distro fix text: `vm-kubuntu`, `vm-fedora-gnome`, `vm-fedora-sway`, `vm-omarchy`; checklist §1)
kind: change

## 1d Process hardening on Linux
files: crates/platform/src/hardening.rs, crates/platform/src/hardening/linux.rs, app/src/main.rs, app/src/browser_status.rs, crates/ipc/src/lib.rs
do: - `harden_process(Role, Stage)` with `Stage::{Start, AfterHandshake}` (macOS/Windows ignore `Stage` and keep their calls). Linux `Start`: `RLIMIT_CORE=0` (exists), `umask(0o077)`, `PR_SET_MDWE(REFUSE_EXEC_GAIN | NO_INHERIT)` (logged, non-fatal: Slint/GPU drivers may need W^X exceptions — measure in the VMs); daemon also `PR_SET_DUMPABLE(0)` at `Start` (nobody needs its `/proc/pid/exe`). UI, CLI and browser host call `AfterHandshake` → `PR_SET_DUMPABLE(0)` right after the daemon verified them (2c), because the daemon reads their `/proc/<pid>/exe` first (ideas §2.2). Port the dumpable/RLIMIT code from Bitwarden `process_isolation/linux.rs` (note the source in a comment).
  - `hardening::is_hardened()` on Linux = dumpable == 0 && (BPF ptrace gate active || Yama ≥ 1); `browser_status::runtime_hardened()` uses it instead of `vk_ipc::has_hardened_runtime()` on Linux.
  - Chains C2 (stacking links) and C3 link 2 register here.
done-when: `cargo test -p vk-platform hardening`; `scripts/check-linux.sh -p vk-platform -p vaultkeeper --all-targets --test` (Docker: dumpable reads back 0, MDWE reads back set, core limit 0)
needs: 1b
difficulty: medium
effort: 1
verify: unit, docker, vm (MDWE under Slint/Mesa on all four VMs)
kind: change

## 1e secure_memory chain exposure and mseal
files: vendor/secure_memory/src/, vendor/PATCHES.md
do: The vendored store already chains `memfd_secret → keyctl → mlock` on Linux; expose which link it took (`SecureKey::backend() -> Backend`), add `mseal` of the `memfd_secret` mapping after it is populated, and register chain C2 with those probes. Keep the diff minimal and record it in vendor/PATCHES.md.
done-when: `cargo test -p secure_memory`; `scripts/check-linux.sh -p secure_memory --all-targets --test` (Docker reports `MemfdSecret` or a reasoned fallback)
needs: 1a
difficulty: medium
effort: 1
verify: unit, docker
kind: change

## 1f Landlock self-sandbox of daemon and UI
files: crates/platform/src/sandbox.rs, crates/platform/src/sandbox/linux.rs, app/src/daemon/mod.rs, app/src/ui_process/mod.rs, crates/platform/Cargo.toml
do: - `sandbox::restrict(Role, &Paths)` with the `landlock` crate at `BestEffort` compatibility: read-only `/usr`, `/etc`, `/proc/self`, `/sys/fs/bpf/vaultkeeper` (status maps), `/dev/null|urandom|dri`, `/run/user/<uid>` (sockets: Wayland, bus, portal), read/write on the data dir, `$XDG_RUNTIME_DIR/vaultkeeper`, log dir, `$XDG_CONFIG_HOME/{vaultkeeper,autostart,systemd/user}`, `$XDG_DATA_HOME/{applications,icons}`; `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL` (the UI is spawned after restriction and inherits the domain, so daemon ↔ UI signals stay allowed); `RESTRICT_SELF` log flags off. Applied after init (fonts, GPU, portals need their paths probed first — collect them from `strace` in the spike VM). The daemon therefore **cannot exec setuid helpers** (`no_new_privs`): the BPF helper is a D-Bus service (4b), and `xdg-open` fallbacks are spawned before restriction or replaced by the OpenURI portal.
  - Chain C6 link 1 (ABI reported; ABI < 8 → Reduced). Fails open with a logged reason when Landlock is disabled.
done-when: `scripts/check-linux.sh -p vk-platform --all-targets --test` (Docker: ruleset builds; ABI ≥ 1); `cargo test -p vk-platform sandbox` (path-set builder on macOS)
deps: landlock@0.4
needs: 1b, 1d
difficulty: hard
effort: 2
verify: docker, vm (daemon and UI run with the ruleset: all four VMs; checklist §2)
kind: change

## 2a Startup permission checks on Linux (refuse or repair)
files: crates/platform/src/fs.rs, crates/platform/src/fs/linux.rs, app/src/os/startup_check.rs
do: `verify_private_dir`/`verify_private_files` on `target_os = "linux"` (fs.rs:75-99 are no-ops on Unix today): `statx` on an `O_PATH | O_NOFOLLOW` fd; refuse a symlink or an owner other than euid; repair modes to 0700/0600 (log). macOS stays the explicit no-op (no behaviour change). startup_check.rs's file list gains `ssh-agent` material and `fido2.bin` (3k).
done-when: `scripts/check-linux.sh -p vk-platform --all-targets --test` (Docker: temp dirs with wrong modes repaired, symlink refused, wrong owner refused via `fakeroot`-free check on a root-owned `/`)
needs: 1b
difficulty: medium
effort: 1
verify: docker, ci
kind: change

## 2b Sockets in the runtime directory
files: app/src/os/layout.rs, crates/platform/src/paths.rs, crates/platform/src/single_instance.rs, crates/ssh/src/socket.rs, docs/USAGE.md
do: On Linux every socket (`cli`, `browser`, `instance`, `ssh`) lives in `$XDG_RUNTIME_DIR/vaultkeeper/` (0700, created with `ensure_private_dir`; refused if `XDG_RUNTIME_DIR` is unset — that is baseline check "runtime dir"), not in the data dir; `SSH_AUTH_SOCK` text and USAGE.md say `$XDG_RUNTIME_DIR/vaultkeeper/ssh.sock`. macOS paths unchanged. The path builder stays a portable pure function with tests.
done-when: `cargo test -p vaultkeeper layout`; `cargo test -p vk-platform paths`; `scripts/check-linux.sh -p vaultkeeper -p vk-ssh --all-targets`
needs: 1b
difficulty: easy
effort: 0.5
verify: unit, docker
kind: change

## 2c Peer identity chain on the Unix transport
files: crates/ipc/src/transport/unix.rs, crates/ipc/src/peer.rs, crates/ipc/src/cli_access.rs, crates/ipc/src/browser/, app/src/daemon/browser/control.rs, app/src/browser_host/mod.rs, crates/ipc/tests/linux_peers.rs
do: - `identify()` on Linux: `SO_PEERPIDFD` → `OwnedFd`; `PIDFD_GET_INFO` → pid, uid, cgroupid (fallback `SO_PEERCRED` when the kernel lacks it; recorded as link 3). `PeerCredentials` gains `pidfd: Option<OwnedFd>` on Linux.
  - `SameExecutable::verify` on Linux: read `/proc/<pid>/exe` (the client is still dumpable at this point, 1d), compare **file identity** — `statx` `(stx_dev, stx_ino, stx_mnt_id)` of the target against our own `/proc/self/exe`, or equal fs-verity digests when both have verity (`FS_IOC_MEASURE_VERITY`) — then `poll(pidfd)` must not report exit. Path strings are never compared (Cellar paths change, ideas §7.5). When the BPF connect gate is active (4c) the check is a mistake guard, as on Windows; a mismatch whose path equals the `opt` path but whose identity differs yields "Vaultkeeper was updated; restart it".
  - `cli_access.rs:84` builds the verifier once: make it re-read our own identity if `/proc/self/exe` ends in ` (deleted)` (the daemon was upgraded) and surface the `Updated` state (2e).
  - **Clients verify the daemon without its `/proc/<pid>/exe`** (ideas §4, §11 C5). The daemon is non-dumpable from `Start` (1d), so the kernel hides its exe link from same-uid readers and today's `verify(&stream.peer_credentials()?, &SameExecutable::current()?)` at `cli_access.rs:212` would fail on every call; the browser host's connect in `app/src/browser_host/mod.rs` (`connect`, `transport::connect` at :144/:153) has the same shape. New `peer::DaemonVerifier` (Linux; macOS wraps today's check unchanged, Windows keeps 2b of the Windows plan) used by `cli_access::exchange` and by the host before its first frame:
    1. before `connect`: open `$XDG_RUNTIME_DIR/vaultkeeper` with `O_PATH | O_NOFOLLOW | O_DIRECTORY`, `statx` → owner = euid, mode 0700, not a symlink; `statx` the socket inode through that dir fd → `S_IFSOCK`, owner = euid;
    2. after `connect`: `SO_PEERPIDFD` (fallback `SO_PEERCRED`) → peer uid = euid; `PIDFD_GET_INFO` → `cgroupid`; read `/proc/<pid>/cgroup` (world-readable even for a non-dumpable task) → path; `statx("/sys/fs/cgroup/<path>")` inode must equal `cgroupid` (binds the name to the pidfd); the name must be a Vaultkeeper unit or app scope (`io.github.avbel.Vaultkeeper.service` from 3g, `app-*io.github.avbel.Vaultkeeper*.{scope,service}` from desktop launches on GNOME/KDE/UWSM); a daemon started outside systemd (terminal, stock Sway) is **Reduced**, not refused; `poll(pidfd)` must not report exit;
    3. the shared BPF probe (4c) reporting `enforcing` upgrades the result to Full: with the `socket_bind` gate only enrolled builds can own a socket under the prefix. Without it, 1–2 are mistake guards (a same-uid process can name its own unit), stated as such in the chain status.
    The daemon's first frame (the TLS certificate frame on the CLI path, the hello on the browser path) gains a small identity record (version, `statx` exe identity, `deleted` flag) so the client can still say "Vaultkeeper was updated; restart it" (2e) without reading the daemon's exe; both ends ship in one build. `control.rs:32` stays server-side (`SameExecutable` for the dumpable host). A mismatch names the failed item.
  - Clients call `harden_process(_, AfterHandshake)` when the server's hello arrives.
  - `#[cfg(target_os = "linux")]` integration tests (`crates/ipc/tests/linux_peers.rs`): pidfd round trip over `UnixStream::pair`; same-exe client accepted; a child `/bin/true` rejected; pid reuse simulated by exiting the peer before `verify` → rejected; **client → non-dumpable daemon**: a child server that calls `PR_SET_DUMPABLE(0)` before `accept` is accepted by `DaemonVerifier` (the regression this bullet exists for); socket in a 0755 directory → rejected naming the mode; socket owned by another uid (simulated through an injected `statx`) → rejected; cgroup binding: `statx` of the child's `/proc/<pid>/cgroup` path equals its `PIDFD_GET_INFO.cgroupid` (cgroup2 on the runner and in Docker); a non-Vaultkeeper cgroup name → Reduced, accepted, status recorded; the identity record round-trips and a `deleted` daemon yields the "updated" error.
done-when: `scripts/check-linux.sh -p vk-ipc --all-targets --test`; `cargo test -p vk-ipc` (macOS unchanged); the `linux` CI job runs `linux_peers`; `cargo test -p vaultkeeper browser_host`
needs: 1d, 2b
difficulty: hard
effort: 2.5
verify: docker, ci
kind: change

## 2d Inherited UI channel on Linux
files: app/src/daemon/launcher.rs, app/src/ui_process/mod.rs, app/src/run.rs, crates/ipc/src/transport/unix.rs
do: The daemon creates a `socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC)`, clears `CLOEXEC` on the child end only for the spawn, and starts `vaultkeeper --ui --ui-fd <n>` (reuse the Windows `--ui-pipe` plumbing and `ui_process::run(…, pipe: Option<usize>)`); the UI checks `SO_PEERCRED` pid == `getppid()` before sending anything, wraps the fd into `RemoteVault::from_stream`. `ui.sock` disappears on Linux (no socket path to squat). macOS keeps `ui.sock`.
done-when: `cargo test -p vaultkeeper launcher`; `scripts/check-linux.sh -p vaultkeeper --all-targets --test`
needs: 2c
difficulty: medium
effort: 1
verify: docker, vm
kind: change

## 2e Upgrade under a running daemon
files: crates/platform/src/install_kind.rs, app/src/daemon/update/mod.rs, app/src/daemon/tray.rs, app/src/cli.rs
do: `install_kind::exe_identity()` (statx + the ` (deleted)` marker) and `install_kind::current_install_path()` (Homebrew: `<prefix>/opt/vaultkeeper/bin/vaultkeeper`; else the realpath at start). State `Updated` when the install path's identity differs from the running one: tray item "Restart to finish the update", CLI connects get the message from 2c, and the daemon re-executes the install path with `--tray` when `quiet_for_update()` holds (same gate as the macOS swap). With BPF installed the restarted daemon reports "this build is not enrolled" (4c) — the enrol prompt follows. The CLI notice (a refusal frame sent to the freshly installed binary) appears only for upgrades from a build that contains this change; older daemons just look unavailable to the new CLI.
done-when: `cargo test -p vaultkeeper update` (state machine with fake identities); `scripts/check-linux.sh -p vaultkeeper --all-targets`
needs: 2c, 6c
difficulty: medium
effort: 1
verify: unit, vm (`vm-kubuntu`, `vm-omarchy`: checklist §12 brew upgrade)
kind: change

## 2f systemd-creds wrapper for the 2FA-remember token
files: crates/platform/src/creds.rs, app/src/daemon/secrets.rs
do: `BlobWrapper` implementation that spawns `systemd-creds --user encrypt --name=vaultkeeper.2fa --with-key=auto -` / `decrypt` (v ≥ 256 [v]); chain C1 link 5: `auto` reports `tpm2+host` when a TPM exists, else `host`; missing `systemd-creds` → no wrapper (warn, token stored sealed only — key-less as today). Portable trait + fake-command tests on macOS.
done-when: `cargo test -p vk-platform creds`; `scripts/check-linux.sh -p vk-platform --all-targets --test` (Docker without systemd: Unavailable with reason)
needs: 0d, 1a
difficulty: medium
effort: 1
verify: unit, docker, vm (`vm-fedora-gnome` with a vTPM; `vm-omarchy` without)
kind: change

## 3a App id, desktop file, icons, portal registration
files: app/src/os/linux/app_id.rs, app/src/os/linux/desktop_entry.rs, app/src/ui_process/mod.rs, app/src/daemon/mod.rs, app/assets/, app/Cargo.toml
do: - `APP_ID = "io.github.avbel.Vaultkeeper"` (design §7.9). Winit app id through Slint's `BackendSelector::with_winit_window_attributes_hook` (`unstable-winit-030` is already on: `hotkey_recorder.rs` imports `slint::winit_030`) calling `WindowAttributesExtWayland::with_name(APP_ID, APP_ID)`.
  - `desktop_entry::ensure()` (daemon start, idempotent): renders the template of ideas §7.3 with the install path from 2e/6c and writes `$XDG_DATA_HOME/applications/io.github.avbel.Vaultkeeper.desktop` plus the hicolor icons (scalable + symbolic SVGs from app/assets) when content differs; runs `update-desktop-database` if present. Portable template + tests.
  - `ashpd` registry: call the host `Registry.Register(APP_ID)` once per process before the first portal call and again on `NameOwnerChanged` of `org.freedesktop.portal.Desktop` (ideas §2.5).
done-when: `cargo test -p vaultkeeper desktop_entry`; `scripts/check-linux.sh -p vaultkeeper --all-targets`
deps: ashpd@0.14
needs: 1f, 2b
difficulty: medium
effort: 1.5
verify: unit, docker, vm (launcher entry and app name in portal dialogs: all four VMs; checklist §3)
kind: change

## 3b Hotkeys: Windows defaults, GlobalShortcuts portal, compositor bindings
files: app/src/settings.rs, app/src/hotkey_recorder.rs, app/src/app/settings_hotkeys.rs, app/src/daemon/hotkey.rs, app/src/daemon/hotkey/linux.rs, app/ui/settings.slint, app/tests/hotkey_recorder.rs, app/tests/generator_settings.rs, app/tests/shortcut_hints.rs, app/tests/shortcut_labels.rs
do: - The cfg table of ideas §10: `DEFAULT_HOTKEY` (`settings.rs:371-375`), `hotkey_display` (:441), `MODIFIER_HINT`/`UNAVAILABLE_NOTICE` (three-way), AltGr warning and `slint_mods` (`settings_hotkeys.rs:55, :82, :301`); test expectations keyed on `target_os = "macos"` vs the rest.
  - Linux backend behind the existing hotkey seam: GlobalShortcuts portal via ashpd (`CreateSession`, `BindShortcuts` with ids `quick-panel`/`generator`, descriptions, `preferred_trigger` from a portable accelerator→trigger converter: `CTRL+SHIFT+space`), `Activated` → the daemon's existing hotkey event plus the `activation_token` when present (GNOME) handed to the UI as `XDG_ACTIVATION_TOKEN`; `ListShortcuts` → `trigger_description` shown in Settings; `ConfigureShortcuts` behind "Change in system settings…". When the portal has no GlobalShortcuts backend (Sway), Settings shows the `bindsym`/`bind =` lines for the detected desktop (`XDG_CURRENT_DESKTOP`) with a copy button; on Omarchy the line is the Lua form for `~/.config/hypr/bindings.lua`: `o.bind("CTRL + SHIFT + SPACE", "Vaultkeeper", "vaultkeeper --search")` [v: Omarchy `o.bind` signature], chosen through the Omarchy marker; `--search`/`--generator` invocations already act as the hotkey (d20f31b). `global-hotkey` stays macOS/Windows only. Chain C9.
done-when: `cargo test -p vaultkeeper hotkey` (converter, three-way strings); `scripts/check-linux.sh -p vaultkeeper --all-targets`; app tests pass on macOS unchanged
needs: 3a
difficulty: hard
effort: 2.5
verify: unit, vm (checklist §4: `vm-fedora-gnome`, `vm-kubuntu` + its Sway session, `vm-fedora-sway`, `vm-omarchy`)
kind: change

## 3c Quick Panel focus and placement
files: app/src/os/linux/activation.rs, app/src/daemon/launcher.rs, app/src/app/quick.rs
do: Chain C10: token from the portal (3b) → token from `XDG_ACTIVATION_TOKEN` in the daemon's own environment when a compositor `exec` binding ran `vaultkeeper --search` (forwarded over IPC to the UI) → new-window focus → `request_activation_token()` from the live UI before showing. `placement` stays the no-op from 0a. The `quick.rs:157` focus hack around system prompts becomes `cfg!(not(target_os = "macos"))` if the polkit/FIDO2 prompt steals focus in the VM (checklist §5 decides).
done-when: `scripts/check-linux.sh -p vaultkeeper --all-targets`; `cargo test -p vaultkeeper quick`
needs: 3b, 2d
difficulty: medium
effort: 1
verify: vm (checklist §5: `vm-kubuntu` first, then `vm-omarchy`, `vm-fedora-sway`, `vm-fedora-gnome`)
kind: change

## 3d Clipboard chain
files: crates/platform/src/clipboard.rs, crates/platform/src/clipboard/linux/, crates/platform/Cargo.toml
do: Chain C8 behind the existing `ClipboardBackend`: `ext-data-control-v1` through wl-clipboard-rs with `text/plain;charset=utf-8` and `x-kde-passwordManagerHint=secret`, timed clear with the SHA-256 rule (KDE, Sway, Hyprland; Omarchy's clipboard history skips exactly this hint [v: `shell/plugins/clipboard/capture.sh`], Klipper too) → RemoteDesktop + Clipboard portal (GNOME): `CreateSession`, `RequestClipboard` before `Start`, `persist_mode` 2 and `restore_token` in the data dir, `SetSelection`/`SelectionWrite` on request, ported from Bitwarden `portal_backend.rs` → `arboard` plain set with the clear timer (Reduced). The probe picks the first link that works on this compositor at startup (`ext_data_control_manager_v1` advertised? portal `RemoteDesktop` available?). Clipboard clear still runs on lock and on timer.
done-when: `cargo test -p vk-platform clipboard` (link selection with fake capabilities); `scripts/check-linux.sh -p vk-platform --all-targets`
deps: wl-clipboard-rs@0.9
needs: 3a
difficulty: hard
effort: 2.5
verify: vm (checklist §6: `vm-fedora-gnome` portal prompt once; `vm-kubuntu` Klipper; `vm-omarchy` Omarchy history skips the entry; `vm-fedora-sway`)
kind: change

## 3e Tray through ksni
files: app/src/daemon/tray.rs, app/src/daemon/tray/linux.rs, app/Cargo.toml
do: Slint's built-in Linux tray hard-codes the id `slint-tray` and pixmaps only [v: i-slint-core 1.19 `ksni.rs`]; use ksni 0.3.7 directly on Linux: `id = APP_ID`, `icon_name` = installed hicolor icon with `icon_pixmap` fallback, the existing menu, `activate` opens the Quick Panel. `Auto` icon theme reads the Settings portal `org.freedesktop.appearance color-scheme` (Blue stays the Windows default; Linux default `Auto`). Watcher absent (GNOME without the AppIndicator extension) → chain C13 "no tray" notice in Settings and the tray-less mode (hotkey and launcher still work). Hosts in the matrix: Plasma, Waybar (Fedora Sway Spin), the Omarchy shell (`Quickshell.Services.SystemTray`), GNOME only with the extension.
done-when: `cargo test -p vaultkeeper tray`; `scripts/check-linux.sh -p vaultkeeper --all-targets`
deps: ksni@0.3
needs: 3a
difficulty: medium
effort: 1.5
verify: vm (checklist §7: `vm-kubuntu`, `vm-fedora-sway` Waybar, `vm-omarchy` shell bar, `vm-fedora-gnome` with/without the extension)
kind: change

## 3f Lock, sleep and session end events
files: crates/platform/src/power.rs, crates/platform/src/power/linux.rs
do: logind over the system bus: `PrepareForSleep(true)` → sleep, `PrepareForShutdown` → `SessionEnding`, the session's `Lock`/`Unlock` signals and `LockedHint` property → screen lock; plus `org.freedesktop.ScreenSaver` `ActiveChanged` (KDE) and `org.gnome.ScreenSaver` `ActiveChanged` (GNOME) on the session bus; Sway/Hyprland lockers reach us through `loginctl lock-session`/`LockedHint` when swayidle/hypridle are configured that way (documented lines in USAGE.md). Chain C14. Same events power.rs exposes on macOS/Windows.
done-when: `scripts/check-linux.sh -p vk-platform --all-targets`; `cargo test -p vk-platform power` (signal → event mapping)
needs: 1b
difficulty: medium
effort: 1
verify: vm (checklist §8: all four; Omarchy locks through its shell + logind inhibit, Sway spin through swayidle/swaylock)
kind: change

## 3g Autostart chain
files: crates/platform/src/autostart.rs, crates/platform/src/autostart/linux.rs, crates/platform/tests/autostart.rs
do: Chain C11 behind the existing autostart API: Background portal `RequestBackground { autostart: true, commandline: [install path, "--tray"], dbus-activatable: false }` (GNOME, KDE) → own user unit `~/.config/systemd/user/io.github.avbel.Vaultkeeper.service` (`PartOf/After/WantedBy=graphical-session.target`, `ExecStart=<install path> --tray`, the hardening options of ideas §11 C6 link 2, `Restart=on-failure`) enabled with `systemctl --user enable` (Omarchy runs UWSM, so this is its link [v]; Sway only with uwsm/sway-systemd) → `~/.config/autostart/io.github.avbel.Vaultkeeper.desktop` → instructions (`exec vaultkeeper --tray` / `exec-once = vaultkeeper --tray`). `is_enabled` reads back whichever link is active; `started_by_login_agent` checks `--tray` (`TRAY_ARG` from 0a returns to use); `refresh` rewrites paths when the install path moved. Templates portable and tested.
done-when: `cargo test -p vk-platform autostart`; `scripts/check-linux.sh -p vk-platform --all-targets`
needs: 3a
difficulty: medium
effort: 1.5
verify: unit, vm (checklist §9: all four VMs; `vm-omarchy` proves the unit route, `vm-fedora-sway` the instructions route)
kind: change

## 3h Open links, file dialogs, network changes
files: app/src/os/misc.rs, app/src/os/linux/open.rs, crates/platform/src/network.rs, crates/platform/src/network/linux.rs, app/Cargo.toml
do: Links open through the OpenURI portal (ashpd). An `xdg-open` fallback is impossible once Landlock applies, so without a portal the UI shows the URL with a copy button ("no portal: open <url> yourself"). File dialogs: `rfd` 0.18 with the `xdg-portal` + `tokio` features (no GTK). Network: NetworkManager `StateChanged`/`PrimaryConnectionChanged` over the system bus (both distros ship NM) → the existing `/alive` probe; NM absent → periodic probe only.
done-when: `scripts/check-linux.sh -p vaultkeeper -p vk-platform --all-targets`; `cargo test -p vk-platform network`
needs: 3a
difficulty: easy
effort: 1
verify: docker, vm
kind: change

## 3i Auto-type chain
files: app/src/os/autotype.rs, app/src/os/autotype/linux.rs
do: Chain: RemoteDesktop portal `NotifyKeyboardKeysym` on a persisted session (GNOME, KDE; shares the persist/restore pattern of 3d but its own session, device type Keyboard) → `zwp_virtual_keyboard_v1` through `wayland-client` with a generated keymap for the text (Sway, Hyprland; the protocol is wlroots-only) → unavailable with the reason in the UI. Restore the previously focused window: not possible on Wayland; the Quick Panel hides itself first and waits for the compositor to refocus (document; design §7.4).
done-when: `scripts/check-linux.sh -p vaultkeeper --all-targets`; `cargo test -p vaultkeeper autotype` (keysym mapping)
needs: 3d
difficulty: hard
effort: 2
verify: vm (checklist §10: `vm-fedora-gnome`, `vm-kubuntu` portal; `vm-omarchy`, `vm-fedora-sway` virtual keyboard)
kind: change

## 3j Quick unlock chain: FIDO2 hmac-secret and presence check
files: crates/platform/src/biometric.rs, crates/platform/src/biometric/fido2.rs, crates/platform/src/biometric/fprintd.rs, crates/platform/src/biometric/envelope.rs, app/src/os/biometrics.rs, app/ui/
do: - Chain C7 behind the biometric enrol/unlock surface: link 1 FIDO2 `hmac-secret` with the vendored `authenticator` 0.5 (enrol: `MakeCredential` with `hmac-secret`, non-resident credential id stored in the envelope; unlock: `GetAssertion` with a 32-byte salt → KEK; UV required when the key supports it, else PIN; envelope v2 primitive id 6 — 3 and 4 stay reserved, 5 is Passport) → link 3 "Fingerprint unlock (key stays in memory)" through fprintd `net.reactivated.Fprint.Device.VerifyStart`/`VerifyStatus` over the system bus → none. Link 2 (TPM2 + PIN) stays out until `tss-esapi` leaves alpha.
  - Labels: `biometric-label` "Security key" / "Fingerprint" (three-way in `os/biometrics.rs:18-35`), `hide_missing_biometric` true on Linux when neither a FIDO2 key nor fprintd is present (`settings_ctl.rs:146`). The passkey UV fallback (`dispatch.rs:505`) uses the same chain.
done-when: `cargo test -p vk-platform envelope biometric` (id 6 round trip, reserved ids); `scripts/check-linux.sh -p vk-platform -p vaultkeeper --all-targets`
needs: 1e, 2a
difficulty: hard
effort: 3
verify: vm (checklist §11, the user's FIDO2 key passed through to `vm-kubuntu` and `vm-omarchy`; fprintd on a laptop or the virtual device; Omarchy: `omarchy setup security fingerprint`)
gate: hardware result from checklist §11 before 5d builds on it
kind: change

## 3k Three-way texts, logs, SSH socket text
files: app/src/app/reprompt.rs, app/src/app/security_key.rs, app/src/app/settings_ctl.rs, app/src/os/log_file.rs, app/src/daemon/update/release.rs, docs/USAGE.md
do: The remaining `cfg!(windows)` texts of ideas §10 become three-way (`reprompt.rs:26`, `security_key.rs:18, :248` "computer", `settings_ctl.rs:21, :367` SSH hint = `SSH_AUTH_SOCK` with the runtime-dir path); `log_dir()` on Linux = `$XDG_STATE_HOME/vaultkeeper/logs` (0700); `release.rs` asset selection knows the Linux tarball names (for the "Download" link of Direct installs). USAGE.md gets a Linux section (install via brew, `security install`, hotkeys per desktop, SSH, autostart lines).
done-when: `cargo test -p vaultkeeper`; `scripts/check-linux.sh -p vaultkeeper --all-targets`
needs: 2b, 3b
difficulty: easy
effort: 1
verify: unit, docker
kind: change

## 3l Settings → Security section
files: app/ui/settings.slint, app/ui/security.slint, app/src/app/settings_ctl.rs, app/src/app/security_ctl.rs, crates/ipc/src/protocol.rs
do: User requirement (2026-11-20): the Settings dialog shows which security solution is in use. A one-line summary at the top of Settings names the overall status and the active mechanisms (for example "Security: Full · BPF LSM · memfd_secret · pidfd · Landlock 11") and opens the section on click. Below it, a new Settings section lists every chain (name, status chip Full/Standard/Reduced/Off, the active link by its mechanism name, the next weaker link that would take over, note, fix) from the daemon's `Report` over IPC, a "Re-check" button, the BPF row with its action button (Install… prints the sudo command and copies it; Enroll… calls the helper over D-Bus, 4c), and the accepted-issues list with "Forget". Hidden on macOS/Windows except the rows that already have content (no behaviour change).
done-when: `cargo test -p vaultkeeper security_ctl` (rendering from fake reports with the Slint testing backend); `scripts/check-linux.sh -p vaultkeeper --all-targets`
needs: 1c, 4c
difficulty: medium
effort: 1.5
verify: unit, vm
kind: change

## 4a BPF LSM spike in the VMs (hardware gate)
files: crates/bpf-helper/bpf/vaultkeeper.bpf.c, crates/bpf-helper/examples/spike.rs, docs/solutions/linux-bpf-spike.md
do: The six programs of ideas §12.3 (`file_open` + `path_*` prefix gate, `ptrace_access_check`, `task_kill`, `unix_stream_connect`, `socket_bind`, `bprm_committed_creds` task storage) with identity = `bpf_get_task_exe_file` → `bpf_get_fsverity_digest` → `enrolled` hash map; a libbpf-rs loader example that pins links and maps under `/sys/fs/bpf/vaultkeeper/`, enrols a digest given on the command line, and enables fs-verity on a path (`FS_IOC_ENABLE_VERITY`). Run on `vm-fedora-gnome` (btrfs; Secure Boot on and off → lockdown integrity/none), `vm-kubuntu` (ext4: expect `EOPNOTSUPP` until `tune2fs -O verity` + reboot) and `vm-omarchy` (btrfs under LUKS, lockdown none, kernel 7.2; then `pacman -S linux-lts` / `linux-hardened` + `omarchy kernel set` to see which kfuncs or LSM entries disappear); record: load/attach result under lockdown integrity, `openat` latency with and without the programs (1 M opens of `/etc/passwd`, and of a file in the protected dir), which paths Slint/winit open at start (for 1f's ruleset), `pkill` denied, `systemctl --user stop` allowed. Write the numbers and the verdicts into docs/solutions/linux-bpf-spike.md.
done-when: `scripts/check-linux.sh -p vaultkeeper-bpf --examples` (the C object compiles with clang in Docker; CO-RE against the vendored `vmlinux.h`); the spike doc exists with the VM results
deps: libbpf-rs@0.27, libbpf-cargo@0.27
needs: 0c
difficulty: hard
effort: 3
verify: docker, vm (`vm-fedora-gnome` SB on/off, `vm-kubuntu`, `vm-omarchy` incl. kernel swap)
gate: the user runs the spike in those VMs; 4b/4c follow its findings
kind: change

## 4b `vaultkeeper-bpf` root helper and system service
files: crates/bpf-helper/, crates/bpf-helper/bpf/, packaging/linux/{vaultkeeper-bpf.service, io.github.avbel.VaultkeeperBpf.conf, io.github.avbel.VaultkeeperBpf.service, io.github.avbel.vaultkeeper.policy}, Cargo.toml
do: - Workspace member `crates/bpf-helper`, binary `vaultkeeper-bpf`, static musl (`libbpf-sys` vendored), no GUI deps; subcommands `install | update | enroll <path> | verify | uninstall | load | unload | status` (ideas §12.5). `install`: copy to `/usr/local/libexec/vaultkeeper/`, write the unit, D-Bus system service files and the polkit policy (actions `…bpf.enroll` auth_admin_keep, `…bpf.register` yes for active sessions, `…quick-unlock` auth_self for C7), `systemctl enable --now`, enable verity on the calling binary (`<opt>/bin/vaultkeeper` resolved to its Cellar realpath), verify `vaultkeeper.verity.minisig` from `share/vaultkeeper/` with the embedded release public key (the updater's key; `minisign-verify` crate or the existing Ed25519 code lifted into a tiny shared crate), `FS_IOC_MEASURE_VERITY`, insert into `enrolled`, `register` the caller's uid with data and runtime dirs into `prefixes`; ext4 without the `verity` feature → print the `tune2fs -O verity <dev>` command and "reboot, then run install again" (btrfs on Fedora and Omarchy, LUKS or not, needs nothing); `bpf` missing from `/sys/kernel/security/lsm` → stop and print the command-line change for the detected system: Omarchy → drop-in `/etc/limine-entry-tool.d/90-vaultkeeper.conf` with `KERNEL_CMDLINE[default]+=" lsm=landlock,lockdown,yama,integrity,bpf"` + `sudo omarchy-refresh-limine` + reboot [i: refresh command]; Ubuntu (26.04) → `GRUB_CMDLINE_LINUX_DEFAULT` + `update-grub`; Fedora → `grubby --update-kernel=ALL --args="lsm=…"`; other → generic text (stock Omarchy, Ubuntu 26.10 and Fedora 45 never hit this); Secure Boot state is only reported (`/sys/kernel/security/lockdown`; Omarchy: off/none); exit codes for each failure. The `Enroll` prompt needs a polkit agent in the session (GNOME Shell, polkit-kde-agent, lxqt-policykit on the Fedora Sway Spin, the Omarchy shell); without one (Kubuntu's optional Sway session) Settings says so and `sudo vaultkeeper-bpf enroll <path>` from a terminal does the same.
  - D-Bus service `io.github.avbel.VaultkeeperBpf` on the system bus (zbus): `Enroll(path) -> digest`, `Register(data_dir, runtime_dir)`, `Status() -> {version, enforcing, enrolled: [digest], my_digest_enrolled}`, each method does `CheckAuthorization` on the caller (pidfd subject) before acting; activated on demand, exits idle after 60 s.
  - Maps pinned 0644 (`status`, `enrolled`) and 0600 (`prefixes`); `load` refuses on a kernel missing a kfunc (CO-RE `bpf_core_type_exists`) and logs to the journal; `unload` unpins (fail-open).
  - Unit tests for argument parsing, policy/unit templates, minisign verification against a fixture; integration test under `#[ignore = "needs root and BPF"]` run by hand in the VM.
done-when: `cargo test -p vaultkeeper-bpf`; `scripts/check-linux.sh -p vaultkeeper-bpf --all-targets --test`; `ruby -e 'require "rexml/document"; REXML::Document.new(File.read("packaging/linux/io.github.avbel.vaultkeeper.policy"))'`
deps: libbpf-rs@0.27, libbpf-cargo@0.27, zbus (present), minisign-verify@0.2
needs: 4a
difficulty: hard
effort: 4
verify: unit, docker, vm (checklist §13: `vm-fedora-gnome`, `vm-kubuntu`, `vm-omarchy`)
kind: change

## 4c BPF links in the chains, probes and the enrol flow
files: crates/linux/src/bpf.rs, crates/platform/src/security/, app/src/daemon/mod.rs, app/src/daemon/security.rs, app/src/cli.rs
do: - One shared probe (ideas §12.9): `lsm` has `bpf` → helper installed (`/sys/fs/bpf/vaultkeeper/status` readable, `enforcing`) → own digest (`FS_IOC_MEASURE_VERITY` on `/proc/self/exe`; `ENODATA` = not enrolled) ∈ `enrolled` → canary (`posix_spawn("/bin/cat", data_dir/.canary)` with a 1 s timeout expecting `EACCES`/`EPERM`). Result feeds link 1 of C1, C3, C4, C5 and the `is_hardened()` of 1d.
  - Enrol flow: state "installed, this build not enrolled" (after `brew upgrade`) → tray and Settings action → `Enroll(install path)` over the system bus → polkit dialog → helper enrols → re-probe. `vaultkeeper security install` prints and (when root) runs the helper's install; `security verify|uninstall` forward likewise.
  - Startup order: the probe runs before the data dir is touched, so an un-enrolled build never trips its own `file_open` denial without a clear message.
done-when: `cargo test -p vk-linux bpf` (status parsing, canary verdicts with fake spawn); `scripts/check-linux.sh -p vaultkeeper -p vk-linux --all-targets`
needs: 4b, 1c
difficulty: medium
effort: 2
verify: unit, docker, vm (checklist §13 on the same three VMs; `vm-fedora-sway` for the enrol prompt through lxqt-policykit)
kind: change

## 4d Release pipeline signs the fs-verity digest
files: .github/workflows/release.yml, scripts/bundle-linux.sh
do: In the Linux build job (6a): `fsverity digest --compact --hash-alg sha256 target/<triple>/release/vaultkeeper` (fsverity-utils from apt) → minisign with `UPDATE_SIGNING_KEY` and trusted comment `vaultkeeper <version> <triple> fsverity` → `share/vaultkeeper/vaultkeeper.verity.minisig` inside the tarball; the helper (4b) checks the comment's version against the binary's `--version`. Unsigned builds (no key) ship no `.minisig` and can only be enrolled with `enroll --unsigned` (developer mode, loud warning).
done-when: `ruby -ryaml -e 'YAML.load_file(".github/workflows/release.yml")'`; `sh -n scripts/bundle-linux.sh`
needs: 6a, 4b
difficulty: easy
effort: 0.5
verify: ci
kind: change

## 5a Browser manifests and the native-messaging proxy
files: app/src/daemon/browser/manifests.rs, app/src/daemon/browser/manifests/linux.rs, app/src/app/settings_browsers.rs, app/ui/
do: Linux manifest directories (ideas §2.6; proxy search list [v: `xnmp-impl.c`]): `~/.mozilla/native-messaging-hosts/`, `$XDG_CONFIG_HOME/{google-chrome,chromium,BraveSoftware/Brave-Browser,microsoft-edge}/NativeMessagingHosts/`; `path` = the install path (opt for Homebrew); manifest name `^\w+(\.\w+)*$`, `type: stdio`. Google Chrome on Omarchy (default browser; `~/.config/google-chrome/NativeMessagingHosts`, binary `/opt/google/chrome/chrome` [s]) and Omarchy's `omarchy-chromium-bin` (`provides chromium`, `~/.config/chromium/…`) are covered by the Chrome/Chromium entries. Detect the snap Firefox (Ubuntu, `/snap/firefox`) and Flatpak Firefox (`~/.var/app/org.mozilla.firefox`), detect `xdg-native-messaging-proxy` (`/usr/libexec/xdg-native-messaging-proxy` or the D-Bus name `org.freedesktop.NativeMessagingProxy`), and show in Settings: "Firefox (snap) needs `widget.use-xdg-desktop-portal.native-messaging-proxy = 1` in about:config (Firefox ≥ 157)". Uninstall removes what we wrote. Portable JSON + path logic tested on macOS.
done-when: `cargo test -p vaultkeeper manifests`; `scripts/check-linux.sh -p vaultkeeper --all-targets`
needs: 3a, 6c
difficulty: medium
effort: 1.5
verify: unit, vm (checklist §14: `vm-kubuntu` Firefox snap + Chrome .deb, `vm-fedora-gnome` Firefox rpm, `vm-omarchy` Chrome default + omarchy-chromium)
kind: change

## 5b Browser host parent identification
files: app/src/browser_host/parent.rs, app/src/browser_host/parent/linux.rs
do: Walk `/proc/<ppid>/{exe,cmdline,status}` (pidfd of the parent first, then read, then liveness check): if the parent is `xdg-native-messaging-proxy`, take the browser from its argv convention (`[host path, manifest, extension id]` in Mozilla mode, `[host path, origin]` in Chromium mode) and from the proxy's own parent; otherwise match the parent's realpath against the allowlist (`/usr/lib/firefox/firefox`, `/snap/firefox/*/usr/lib/firefox/firefox`, `/usr/lib64/firefox/firefox`, `/opt/google/chrome/chrome`, `/usr/lib/chromium/chromium`, `/usr/lib64/chromium-browser/chromium-browser`, `/opt/brave.com/brave/brave`, `/opt/microsoft/msedge/msedge`); `bwrap` (Flatpak) → unknown → today's "unknown browser" prompt. Chain C12. The chain-walk rules are a portable function over plain process records with macOS tests.
done-when: `cargo test -p vaultkeeper parent`; `scripts/check-linux.sh -p vaultkeeper --all-targets`
needs: 2c
difficulty: medium
effort: 1.5
verify: unit, vm (checklist §14 on `vm-kubuntu`, `vm-fedora-gnome`, `vm-omarchy`)
kind: change

## 5c Browser status gate, socket and tests on Linux
files: app/src/browser_status.rs, app/src/daemon/browser/control.rs, app/src/browser_host/mod.rs, app/tests/browser_daemon/
do: `runtime_hardened()` = `hardening::is_hardened()` (1d) on Linux; the browser socket lives in the runtime dir (2b) and the host connects through the transport with the peer check (2c) — with BPF the connect gate protects it. The browser daemon test harness runs on Linux CI (sockets in a temp `XDG_RUNTIME_DIR`).
done-when: `scripts/check-linux.sh -p vaultkeeper --all-targets --test`; `cargo test -p vaultkeeper --test browser_daemon` in the `linux` job
needs: 5a, 5b, 1d
difficulty: easy
effort: 1
verify: docker, ci
kind: change

## 5d Passkeys and save prompts on Linux
files: app/src/daemon/browser/dispatch.rs, app/src/app/
do: The passkey user-verification fallback (`dispatch.rs:505`) uses the C7 chain (3j); save/fill prompts open as Slint windows with the activation token when the browser handed one via the proxy (none today → new-window focus). No new protocol.
done-when: `cargo test -p vaultkeeper`; `scripts/check-linux.sh -p vaultkeeper --all-targets`
needs: 3j, 5c
difficulty: easy
effort: 0.5
verify: vm (checklist §14)
kind: change

## 6a Release job: Linux tarballs
files: .github/workflows/release.yml, scripts/bundle-linux.sh, packaging/linux/
do: - Job `linux-build`, matrix `{x86_64: ubuntu-latest, aarch64: ubuntu-24.04-arm}` (glibc 2.39 build host, older than both targets): apt deps (0b list + `fsverity`), rust-cache `shared-key: linux-release` `save-if: false`, `cargo build --release --locked -p vaultkeeper -p vaultkeeper-bpf --target <triple>`, `strip`; `scripts/bundle-linux.sh` lays out `vaultkeeper-v<ver>-<triple>/{bin/vaultkeeper, libexec/vaultkeeper-bpf, share/vaultkeeper/{io.github.avbel.Vaultkeeper.desktop.in, icons/…, install-kind (homebrew), bpf/vaultkeeper.bpf.o}, LICENSE}` → `.tar.gz`; `ldd bin/vaultkeeper` is printed and checked against the allowed runtime library list (ideas §7.6) so a new dynamic dependency fails the job. The existing `release` job downloads both tarballs, signs them with minisign (`.minisig`, trusted comment `vaultkeeper <version> <asset>` as 5g of the Windows plan) and adds them to `SHA256SUMS`.
  - The `install-kind` marker is written per packaging target by the bundle script (`homebrew` here; `deb`/`rpm` in 9a).
done-when: `ruby -ryaml -e 'YAML.load_file(".github/workflows/release.yml")'`; `sh -n scripts/bundle-linux.sh`; a `workflow_dispatch` run produces both tarballs
needs: 0c, 3a
difficulty: medium
effort: 1
verify: ci
kind: change

## 6b Homebrew formula and the tap bump job
files: .github/workflows/release.yml, packaging/homebrew/vaultkeeper.rb.erb, scripts/bump-homebrew.rb; in avbel/homebrew-tap: Formula/vaultkeeper.rb
do: - `Formula/vaultkeeper.rb` from the template of ideas §7.7: `on_linux { on_intel { url …x86_64-unknown-linux-gnu.tar.gz; sha256 } on_arm { …aarch64… } }`, no `on_macos`, `install` puts `bin/`, `libexec/`, `share/vaultkeeper/` in place, `caveats` (first start writes the launcher entry; `sudo #{opt_libexec}/vaultkeeper-bpf install` for BPF protection; runtime packages for apt and dnf; "Start at login" lives in Settings), `test do assert_match version.to_s, shell_output("#{bin}/vaultkeeper --version")`. No `service do` (ideas §7.4).
  - Job `homebrew` (environment `homebrew`, needs `release`, tags only): checkout `avbel/homebrew-tap` with `HOMEBREW_TAP_TOKEN` (fine-grained PAT, contents: write on that repo), `scripts/bump-homebrew.rb <version> SHA256SUMS` rewrites `version` and both `sha256` lines, `ruby -c`, commit `vaultkeeper <version>` with the workflow bot identity, push. The first formula is committed to the tap by the user (the job only updates).
done-when: `ruby -c packaging/homebrew/vaultkeeper.rb` (rendered); `ruby -ryaml -e 'YAML.load_file(".github/workflows/release.yml")'`; `brew install avbel/tap/vaultkeeper` installs and `vaultkeeper --version` runs on `vm-kubuntu`, `vm-fedora-gnome` and `vm-omarchy` (Homebrew on Arch: `base-devel procps-ng curl file git` are present on Omarchy [i])
needs: 6a
difficulty: medium
effort: 1
verify: ci, vm (checklist §12 on `vm-kubuntu`, `vm-fedora-gnome`, `vm-omarchy`)
kind: change

## 6c Install-kind detection and the updater under a package manager
files: crates/platform/src/install_kind.rs, app/src/daemon/update/mod.rs, app/src/settings.rs, app/ui/settings.slint, app/src/app/settings_ctl.rs, app/src/daemon/tray.rs, app/src/cli.rs
do: `InstallKind::detect()` (ideas §8: marker file `../share/vaultkeeper/install-kind` → Homebrew path shape → dpkg `.list` → `rpm -qf` → `Direct`; macOS/Windows return `Direct` for now), `manager()` → "Homebrew" | "apt" | "dnf". When managed: settings load clamps `auto_update = false` in memory (never written), `Updater::spawn` sets `Status::Managed(manager)` and starts no task, the tray omits "Check for Updates…", `settings.slint:258` shows a static "Updates: managed by Homebrew — `brew upgrade vaultkeeper`" row, `vaultkeeper --version` prints `install: homebrew`. `Direct` keeps today's behaviour.
done-when: `cargo test -p vk-platform install_kind` (all branches with injected paths); `cargo test -p vaultkeeper update settings`; `scripts/check-linux.sh -p vaultkeeper --all-targets`
needs: 0d
difficulty: medium
effort: 1
verify: unit, vm (checklist §12)
kind: change

## 7a Linux test checklist and memory measurement
files: docs/solutions/linux-test-checklist.md, scripts/measure-linux.sh
do: The checklist in the appendix of this plan, one section per desktop variant and per risk, becomes docs/solutions/linux-test-checklist.md; `scripts/measure-linux.sh` prints the daemon's and the UI's `RssAnon`/`Pss` from `/proc/<pid>/smaps_rollup` (tray only, Quick Panel shown, 10 s after close) next to the macOS numbers.
done-when: both files exist; `sh -n scripts/measure-linux.sh`
needs: 0c
difficulty: easy
effort: 0.5
verify: —
kind: change

## 7b Docs: Linux status
files: docs/solutions/linux-support.md, docs/solutions/linux-gaps.md, docs/USAGE.md
do: "Implementation" header in linux-support.md linking this plan, the checklist and the spike doc; the §1 floor table and the desktop/portal matrices from ideas §1; the decided items (Homebrew first, BPF first link, baseline flag, Ctrl+Shift+Space, D-Bus helper instead of pkexec, no `service do`, Hyprland on Omarchy and Ubuntu but not Fedora); mark design §5.5 setgid as "deb/rpm tier only, if ever" and §5.6 as implemented by phase 4. Propose a new README Linux section for the user's approval: README.md:215-232 is out of date (it promises Wayland data-control clipboard everywhere, AppImage/Debian/RPM packages and polkit quick unlock); edit README only after approval.
done-when: `grep -q "Implementation" docs/solutions/linux-support.md`
needs: 6b, 4c
difficulty: easy
effort: 0.5
verify: —
kind: change

## 7c Review of all Linux changes
files: .plan/linux-support.md
do: Done by the orchestrator: a review agent on Sonnet at xhigh effort (the repo memory forbids Opus at high effort) reviews `git diff main...linux-support` for correctness, security (BPF programs and helper first), and macOS/Windows regressions; fix CRITICAL and HIGH findings before 8a.
done-when: review findings addressed
needs: 7b
difficulty: easy
effort: 1
verify: —
kind: change

## 7d Linux requirements document
files: docs/solutions/linux-requirements.md, docs/USAGE.md, app/src/os/security_gate.rs
do: The table of ideas §9.1 as a user-facing document: item, what the probe checks, Refuse/Warn/Status, what a missing item disables or why it blocks startup, and the fix on Ubuntu 26.10, Fedora 45 and Omarchy (pacman/omarchy commands; a note that any other Arch setup is unsupported and runs only if these probes pass). `vaultkeeper security requirements` renders the same table from the same source (a const table in `security_gate.rs`), and a unit test regenerates the Markdown and compares it with the committed file so the doc and the binary cannot drift. USAGE.md links it from the Linux section.
done-when: `cargo test -p vaultkeeper requirements_doc` (generated Markdown equals docs/solutions/linux-requirements.md); the file exists
needs: 1c
difficulty: easy
effort: 1
verify: unit
kind: change

## 8a Pull request and CI check
files: .plan/linux-support.md
do: Done by the orchestrator: open the PR to main after the last phase commit; every `linux*` job in ci.yml passes; the four VM checklists are attached.
done-when: `gh pr checks --watch` reports all checks passing
needs: 7c, 7d
difficulty: easy
effort: 0.5
verify: ci
kind: change

## 9a .deb and .rpm packages (later phase)
files: packaging/linux/deb/, packaging/linux/rpm/, .github/workflows/release.yml, scripts/bundle-linux.sh
do: `cargo-deb` and `cargo-generate-rpm` from the same release build: `/usr/bin/vaultkeeper`, `/usr/libexec/vaultkeeper/vaultkeeper-bpf` (root at install time, so `postinst`/`%post` run `vaultkeeper-bpf install --system` straight away: unit, D-Bus service, policy; per-user enrol stays a user action), `/usr/share/applications/io.github.avbel.Vaultkeeper.desktop`, icons, `/usr/share/vaultkeeper/install-kind` = `deb`/`rpm`, `/usr/share/vaultkeeper/vaultkeeper.verity.minisig`; `postinst` enables verity on `/usr/bin/vaultkeeper` and enrols it (root, so no prompt); `%systemd_user_postun_with_restart` / `deb-systemd-invoke --user` restart the user unit where it exists (ideas §2.7). Repos (apt/dnf) are a separate decision; GitHub release assets first.
done-when: `ruby -ryaml -e 'YAML.load_file(".github/workflows/release.yml")'`; `dpkg -I` and `rpm -qpl` list the files; install/upgrade/remove in both VMs
needs: 8a
difficulty: medium
effort: 2
verify: ci, vm
kind: change

## Parallel tracks and critical path
Tracks after 1b (all need 0a–0d first):
- **T1 identity and storage**: 2a → 2b → 2c → 2d; 2f after 0d.
- **T2 desktop**: 3a → {3b → 3c, 3d → 3i, 3e, 3g, 3h}; 3f and 3k any time after 1b/2b; 3j after 1e + 2a; 3l after 1c + 4c.
- **T3 BPF**: 4a right after 0c (spike code is independent of the app) → 4b → 4c; 4d after 6a.
- **T4 browser**: 5a after 3a + 6c; 5b after 2c; 5c after 5a, 5b, 1d; 5d after 3j.
- **T5 packaging**: 6c after 0d; 6a after 0c + 3a; 6b after 6a; 7a any time; 7d after 1c.
Critical path (person-days): 0a 0.5 → 0b 0.5 → 0c 0.5 → 1a 1 → 1b 2 → 1d 1 → 2b 0.5 → 2c 2 → 2d 1 → 3a 1.5 → 3b 2.5 → [4a 3 runs in parallel from 0c] → 4b 4 → 4c 2 → 3l 1.5 → 6a 1 → 6b 1 → 7b 0.5 → 7c 1 → 8a 0.5 ≈ **24 days** of dependent work, dominated by 1b → 2c → 3b and 4b → 4c. Total effort of all steps 0a–8a ≈ 59.5 person-days; with two parallel tracks ≈ 6–7 calendar weeks to the Homebrew release, deb/rpm (9a) after.
The two hardware gates (4a spike results; 3j FIDO2/fprintd) are the schedule risks: start 4a in week 1.

## Open decisions (recommendation first)
1. **Branch base.** Resolved: `windows-support` was merged into main (PR #2, c5c1bbc; PRs #3–#5 since), so SealedFileStore, the transport seam and the startup checks are on main. The `linux-support` branch starts from main when the user says so.
2. **Ubuntu 26.10 over 26.04 LTS** (ideas §1): latest release, `bpf` in `CONFIG_LSM`, kernel 7.3, GNOME 51, Plasma 6.7.5, Hyprland 0.56; 26.04 = "may work", revisit at 26.04.2 (HWE 7.3 kernel).
3. **Hyprland on Fedora 45**: not packaged and no F45 COPR build on 2026-11-20 → Hyprland is tested on Ubuntu 26.10 only; Fedora Hyprland unsupported until a COPR ships it.
4. **BPF identity verification**: helper-side minisign over the fs-verity digest + root-owned map (recommended; same key as the updater) vs in-kernel `bpf_verify_pkcs7_signature` (needs an RSA/ECDSA X.509 key in a world-searchable keyring; later hardening).
5. **Privileged interface**: D-Bus system service with polkit checks (recommended; works under Landlock/`no_new_privs`, no TOCTOU on user-writable paths) vs `pkexec` of the helper.
6. **Signals link (C4)**: deny every user-initiated signal to Vaultkeeper from non-allowlisted senders (recommended; allowlist = Vaultkeeper, root, the user's systemd; `pkill` stops working, `vaultkeeper --quit` and `systemctl --user stop` do) vs deny only SIGSTOP/SIGCONT/SIGKILL vs opt-in toggle.
7. **Quick unlock on the Homebrew tier**: FIDO2 hmac-secret first, fprintd presence-only second (recommended); polkit `auth_self` action arrives with the helper install; TPM2 deferred.
8. **Clipboard on GNOME**: RemoteDesktop + Clipboard portal with one persisted permission prompt (recommended) vs plain `arboard` (no concealment, no prompt).
9. **`service do` in the formula**: omit (recommended); autostart through the C11 chain.
10. **seccomp in v1**: no (recommended; Landlock + MDWE + BPF; a syscall allowlist under Slint/Mesa needs its own test cycle).
11. **MDWE**: on by default, off if the spike shows Mesa/Slint needing W^X (decided by 4a).
12. **GNOME tray without the AppIndicator extension**: Settings notice + tray-less mode (recommended); Fedora users `dnf install gnome-shell-extension-appindicator`. Not: shipping our own extension.
13. **Firefox Flatpak (Fedora)**: supported only through the proxy with the Firefox pref; otherwise "unsupported" in Settings (recommended).
14. **Hyprland hotkey**: document both `global` (xdph) and `exec vaultkeeper --search` bindings; default instructions use `exec` (works without xdph quirks).
15a. **Arch = Omarchy only** (user): Omarchy v4.5.0 defaults are the floor for Arch (kernel `linux-omarchy` 7.2, `lsm=landlock,lockdown,yama,integrity,bpf`, Hyprland 0.57.2 + xdph 1.5.0, Omarchy shell as tray and polkit agent, UWSM, Limine UKI, btrfs + LUKS, Secure Boot off, Chrome). Plain Arch, `linux-lts`, `linux-hardened`: unsupported; the probes decide and the refusal names the `pacman`/`omarchy` fix. Recommend stating the kernel floor as "7.2 (Omarchy) / 7.3", features by probe.
15b. **Kernel floor vs `linux-lts`** (6.18): every kernel feature except Landlock ABI ≥ 8 exists; recommend `Warn` (C6 Reduced), not refuse, so an Omarchy user on linux-lts keeps running with a visible badge.
15c. **Fedora Sway Spin polkit agent**: sway-config-fedora requires lxqt-policykit [v]; whether it is autostarted is checked in `vm-fedora-sway`; if not, Settings shows the `exec lxqt-policykit-agent` line (Status, never refuse).
15. **Dynamic link allowlist** (6a): fail the release job on an unexpected `ldd` entry (recommended) so the formula's runtime package list stays true.

## Appendix: manual test checklist (draft of docs/solutions/linux-test-checklist.md, step 7a)

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
- [ ] C2 shows `memfd_secret`; `grep Secretmem /proc/meminfo` grows after unlock; `/proc/<pid>/maps` shows the sealed mapping.
- [ ] Landlock active (C6 Full, ABI 11): the daemon cannot read `~/Documents` (check with the `security verify` self-test); fonts, GPU, portals, tray and D-Bus still work on all four desktops; MDWE on: no crash in Slint/Mesa (else record and flip decision 11).
- [ ] UI runs under the same ruleset; file dialogs (portal) still open and save.

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
- [ ] GNOME/KDE: "Start at login" on → Background portal entry (`~/.config/autostart/` file written by the portal); reboot → tray present; off → removed.
- [ ] `vm-fedora-sway` and the Kubuntu Sway session (stock config): Settings shows the `exec` line. `vm-omarchy` (UWSM): the user unit route works (`systemctl --user status io.github.avbel.Vaultkeeper`; starts after `graphical-session.target`, tray appears after login).
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
