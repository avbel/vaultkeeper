# Vaultkeeper on Windows 11: research

Scope: Windows 11 24H2 (build 26100) and newer, x64 and ARM64. Biometrics through Windows Hello only (no WinBio, no
direct sensor access). Date: 2026-11-13.
Marks: **[v]** = checked in a primary source or in code during this research; **[i]** = inferred or from memory, check on a
real machine. Design recommendations in §3–§5 and §8 come from a security design review (Fable) of this research.

## 0. Short answers

| Question | Answer |
|---|---|
| How hard? | Medium. Crypto, API, vault, generator and most of the UI are portable, and several Windows pieces already exist in crates we use: Slint's tray, `global-hotkey`, `arboard`, `auto-launch` and the vendored SSH agent's named-pipe listener. Most of the new work is security plumbing: named-pipe IPC, file ACLs, process hardening, Windows Hello, `webauthn.dll` for security keys, and code signing. Estimate: MVP 6–9 weeks, parity with macOS 15–20 weeks (one developer, §11). |
| Windows Hello instead of Touch ID? | Wrap the user key to a Hello-gated RSA key in the Microsoft Passport key storage provider (NCrypt). Enrolment encrypts to its public key without a prompt; each unlock is one Hello-gated decrypt. That is the same shape as the Secure Enclave design, and unlike Bitwarden's and KeePassXC's "hash a Hello signature" trick it does not rely on signatures being deterministic, which Microsoft never promised. Keep the persistent mode, so a restart needs no master password. Needs a spike on real hardware first (§3). |
| How to organise encryption and file permissions? | Everything goes in `%LOCALAPPDATA%\Vaultkeeper`, not Roaming. One protected ACL on the directory: user, SYSTEM and Administrators, plus a "no read up" integrity label. The refresh token is sealed under a key derived from the user key (the Linux design) and then DPAPI-wrapped. The 2FA-remember token is DPAPI only. The Hello file is bound to the TPM key. No Credential Manager. Startup checks repair or refuse (§4). |
| ARM64 easy to add? | Yes. `aarch64-pc-windows-msvc` has been Tier 1 since Rust 1.91 [v], GitHub's `windows-11-arm` runners are GA for public repos [v], and the only crate in the tree that compiles C is `aws-lc-sys`, which needs clang-cl on ARM64 [v]. An x64 build also runs on ARM64 under emulation [i]. The cost is a second CI job, a second installer and a Hello test on real Snapdragon hardware: about 2–4 days (§9). |
| Is 24H2 a good floor? | Yes. Only the detached console policy needs it, and that policy lets one binary serve both the GUI and the CLI (§7.11) [v]. The recommended Hello design uses Windows 10-era APIs. Home/Pro 24H2 servicing ended 2026-10-14; Enterprise/Education 24H2 runs to 2027-10-13 [v]. |
| Can it ship self-signed like the macOS build? | No. Smart App Control blocks unsigned and self-signed apps when its cloud check is unsure, and users can now turn it on without reinstalling [v]. SignPath Foundation signs open-source projects for free [v] (§8). |
| Tray icon | Default Blue, with Auto, White and Black as options (§7.1). |

## 1. What changes compared with the README roadmap

| README "Phase 3: Windows" says | Research result |
|---|---|
| Credential Manager or DPAPI for tokens | No Credential Manager. The refresh token is sealed under the user key (shared with Linux) and wrapped in DPAPI; the 2FA-remember token is DPAPI only (§4). Credential Manager is DPAPI underneath, readable by any same-user process, capped at 2560-byte blobs [i], and lives outside the account directory that log out deletes. |
| Windows Hello for biometrics | Concrete design: NCrypt Passport KSP, hybrid RSA/AES wrap, persistent across restarts, prompt owned by the daemon but parented to the UI's window (§3). |
| IPC over named pipes with a client process check | UI: a GUID-named pipe whose two ends the daemon opens itself, handing the client end to the UI at spawn, so only a one-line check remains. CLI and browser host: SID-named pipes with `FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS` and a DACL that does not grant "create instance". The peer check is a mistake guard, as on Linux (§5). |
| The Windows OpenSSH agent named pipe | The vendored `ssh_agent` already has it (`\\.\pipe\openssh-ssh-agent`, tokio named pipes, client pid via `GetNamedPipeClientProcessId`) [v: `vendor/ssh_agent/src/server/listener/windows.rs`]. It needs a patch: explicit DACL and `FILE_FLAG_FIRST_PIPE_INSTANCE`; without the flag, instances of a second agent would be served in turn (§7.10). The built-in "OpenSSH Authentication Agent" service, which uses the same name, is disabled by default [v: secondary source]. |
| Autostart through the registry Run key | `auto-launch` 0.6 already writes `HKCU\…\CurrentVersion\Run` and reads `…\Explorer\StartupApproved\Run`, where Settings → Apps → Startup records a user's "off" [v: crate source]. Show that state in Settings. |
| Auto-type through `SendInput` | Right: `KEYEVENTF_UNICODE` key pairs, as Bitwarden does [v: `autotype/src/type_input/windows.rs`]. Unlike macOS it needs no permission. It cannot type into elevated windows (UIPI) [i]. |
| (missing) | Data dir moves from Roaming to Local AppData; `fs.rs` permissions are `cfg(unix)` only; process hardening (§5.1); console subsystem for the CLI (§7.11); security keys need `webauthn.dll` (§7.9); Chromium starts native hosts through `cmd.exe` (§7.8); clipboard history and cloud exclusion (§7.4); Recall and screen-capture exclusion (§7.12); code signing and an Ed25519 update key (§8). |

Code that is macOS-only today, found with `grep -rln 'target_os = "macos"'`: 26 files, 143 lines. The bulk is in
`crates/platform` (biometric, keychain, fs, hardening, paths, power, network, clipboard, code_signature), `crates/ipc/src/peer.rs`,
`app/src/os/*`, `app/src/browser_host/parent.rs` and `vendor/ssh_agent/src/server/peer_info.rs`. Sixteen files use
`UnixStream`/`UnixListener` (IPC client and server, browser socket, CLI socket, single instance, SSH socket and tests).

## 2. Windows versions

| Item | Status |
|---|---|
| Support floor | 24H2 (build 26100). 25H2 and 26H2 are the current releases [v]. |
| End of servicing | Home/Pro: 24H2 2026-10-14, 25H2 2027-10-13, 26H2 2028-10-10. Enterprise/Education: 24H2 2027-10-13 [v: Microsoft Lifecycle]. Un-updated 24H2 Enterprise/LTSC is the oldest population to test. |
| 26H1 | Its own release line, serviced to 2028 [v]. It is reported to ship only on new Snapdragon devices [i]. ARM64 builds should be tested on it. |
| `consoleAllocationPolicy` (detached) | 24H2+ [v]. A manifest element: older systems ignore it, so no runtime check. |
| `KeyCredentialManager.RequestCreateForWindowAsync`, `KeyCredential.RequestSignForWindowAsync`, `RequestDeriveSharedSecretAsync`, the 8-argument `RequestCreateAsync` | Listed under the 26100 SDK [v]. The 26100 branch receives new WinRT APIs through cumulative updates, so their presence at 24H2 release is doubtful [i]. If used, check with `ApiInformation::IsMethodPresent`. `windows` 0.62.2, the latest published crate, has no bindings for them [v: crate source]. The recommended design does not use them. |
| NCrypt Passport KSP properties, `IUserConsentVerifierInterop` | Windows 10-era [i] |
| TPM 2.0 | Required by Windows 11's hardware spec, but VMs and bypassed installs may lack it [i]. Hello keys are then software keys. |
| Smart App Control | Users can turn it on without a clean install [v] |

## 3. Windows Hello

### 3.1 The primitives

| Primitive | Who uses it | Enrolment prompts? | Weak point |
|---|---|---|---|
| `KeyCredentialManager` + `RequestSignAsync(challenge)` → SHA-256 → AES key | Bitwarden (persisted), KeePassXC (in memory only) [v: both sources] | Yes | Depends on deterministic signatures. Microsoft documents KeyCredential signatures as "PKCS #1 RSA PSS with SHA256" [v: Learn, prerelease-tagged page]; salted PSS would make every derived key different. It works today, so the implementation is PKCS#1 v1.5 [i]. Also WinRT, and focus hacks before the *ForWindow* APIs. |
| NCrypt with `MS_NGC_KEY_STORAGE_PROVIDER` (Microsoft Passport KSP): RSA key, `NCryptDecrypt` | KeePassWinHello [v] | Only when the key is first created | Thinly documented KSP [i]. Face unlock failed with `0x80098044` (`WINBIO_E_INVALID_TICKET`) when the Hello dialog was not in the foreground; PIN was unaffected [v: issue #120, PR #159]. |
| `KeyCredential.RequestDeriveSharedSecretAsync(WindowId, message, encryptedRequest)` | Nobody known | ? | Undocumented beyond its signature, newer than 24H2 RTM, no Rust bindings [v]. |
| `UserConsentVerifier` yes/no, key held in DPAPI-protected memory | Bitwarden's "ephemeral" path [v] | No | No key at rest, but the locked vault keeps its key in memory. |

### 3.2 Recommendation: NCrypt Passport KSP, hybrid wrap

- **Key.** One RSA-2048 key per Windows user in the Passport KSP. The KSP's names take the form `<SID>//<domain>/<sub>/<name>`;
  KeePassWinHello's is `<SID>//KeePassWinHello//KeePassWinHello` [v: from its issue thread], ours would be
  `<SID>//Vaultkeeper//Vaultkeeper` [i: exact format]. Creating it (`NCryptCreatePersistedKey` + `NCryptFinalizeKey`) prompts once per
  machine [i].
- **Enrol, no prompt.** `NCryptExportKey(BCRYPT_RSAPUBLIC_BLOB)`, then RSA-OAEP-SHA256 (`NCRYPT_PAD_OAEP_FLAG`) of a fresh random 32-byte
  key-encryption key, then AES-256-GCM of the user key under that key. If the KSP refuses OAEP, fall back to PKCS#1 v1.5 padding [i].
  Re-enrolling after a user-key rotation, or for a second account, needs no prompt, as on macOS. With the signature trick
  Bitwarden has to keep the derived key in DPAPI memory to avoid a second prompt [v].
- **Unlock, one prompt.** `NCryptDecrypt` on the wrapped key, with `NCRYPT_WINDOW_HANDLE_PROPERTY` (parent window, §3.3),
  `NCRYPT_USE_CONTEXT_PROPERTY` (prompt text, chosen by the daemon) and `NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY` = 1, so the
  KSP's PIN cache never lets an unlock through without a fresh gesture [i]. With a TPM the decrypt runs inside it [i].
- **Persistent mode stays**, unlike Linux. The file at rest is useless without a Hello gesture, so the Linux reason for
  ephemeral-only (any process can read Secret Service) does not apply. Keep "Require master password on app start". Keep the
  macOS invariant "locking zeroizes the user key"; every unlock is one decrypt, with no Bitwarden-style key held while locked.
- **Envelope.** Mirror `biometric/envelope.rs`, version 2:
  `magic ‖ version ‖ primitive_id ‖ key name ‖ public key blob ‖ user SID ‖ wrapped KEK ‖ nonce ‖ ciphertext+tag`, length-prefixed, the
  whole header as AES-GCM associated data. Primitive ids: 1 = Secure Enclave P-256 ECDH (macOS), 2 = Passport RSA-OAEP KEK, 3 = reserved
  for the KeyCredential signature PRF, 4 = reserved for `RequestDeriveSharedSecretAsync`. Store the public key so unlock can tell a
  recreated key (a PIN reset deletes the container) and report `BiometricInvalidated`, not a decrypt error. Switching primitive
  later is a new id; the old one is rejected as "enrol again".
- **Errors** keep the invariant from `biometric.rs`: only definitive outcomes are `BiometricInvalidated`, because the app deletes
  the enrolment on it. Definitive means the key is gone (`NTE_BAD_KEYSET`/`NTE_NO_KEY`), the stored public key does not match the key
  in the KSP, or the AES-GCM tag fails after a successful unwrap → enrol again. Every other NCrypt or Hello status (cancel, no
  match, lockout, TPM busy, `0x80098044` after its retry, an unknown code) → `BiometricFailed`, master password this time.
- If the signature path (id 3) is ever used, sign the challenge twice at enrolment and refuse to persist unless both signatures
  match.

### 3.3 Which process prompts

The daemon owns the key, so it calls `NCryptDecrypt`. The UI process owns the foreground, and a Hello dialog that is not in the
foreground fails face unlock (§3.1). Flow:

1. The user clicks "Unlock with Windows Hello". The UI calls `AllowSetForegroundWindow(daemon_pid)` and sends
   `UnlockWithHello { hwnd }`.
2. The daemon checks `IsWindow(hwnd)` and that `GetWindowThreadProcessId(hwnd)` is the UI's pid, sets it as
   `NCRYPT_WINDOW_HANDLE_PROPERTY`, and decrypts. A window from another process as owner is fine: the dialog runs in a system
   broker anyway [i].
3. On `0x80098044`, retry once at once, since the dialog is now in the foreground.

Pitfalls: suspend the Quick Panel's hide-on-deactivate while a prompt is up, and keep the window alive until the daemon
answers. Do not copy Bitwarden's focus hacks: `SPI_SETFOREGROUNDLOCKTIMEOUT` with `SPIF_UPDATEINIFILE` persists a system
setting if we crash mid-prompt, and `FindWindowA("Credential Dialog Xaml Host")` would foreground any window with that class,
including a spoof [v: `windows_focus.rs`].

"SSH requires Windows Hello" has the same shape in the daemon:
`IUserConsentVerifierInterop::RequestVerificationForWindowAsync(ui_hwnd, message)` [v: binding in `windows` 0.62]. That needs WinRT, so
`RoInitialize(RO_INIT_MULTITHREADED)` on that worker thread [i].

### 3.4 Security model compared with macOS

- Any Hello gesture unlocks, including the PIN; the PIN is Hello's root. The feature is "Windows Hello", not "fingerprint".
- Adding or removing a fingerprint or face does not invalidate the key; there is no `.biometryCurrentSet` equivalent [i]. Removing
  Hello or a destructive PIN reset deletes the key → "enrol again" [i].
- The Passport key is per Windows user, not per app [i]. Any same-user process can call `NCryptDecrypt` on it with its own
  prompt text, so the realistic attack is a spoofed prompt the user approves. That is the same class as the macOS "Touch ID prompt
  phishing" risk in the architecture doc.
- Hello is unavailable over RDP and on a locked session [i]; check availability before offering the button.
- Covers: a stolen disk or backup, other local users, someone at an unattended machine with a locked vault. Does not cover: a
  same-user process that gets the user to approve a prompt, admin or kernel.

### 3.5 UI changes

The Touch ID list in `linux-support.md` §3.4 applies as written: one `biometric-label` property ("Touch ID" / "Windows Hello"),
`touch-id-*` properties renamed to `biometric-*`, the enrol row hidden when Hello is unavailable (`KeyCredentialManager.IsSupportedAsync`
or a probe of the KSP), and the passkey user-verification fallback in `app/src/daemon/browser/dispatch.rs`. Unlike Linux, "Require master
password on app start" stays visible.

## 4. Secrets at rest and file permissions

### 4.1 What protects each file

| Data | Protection | Why |
|---|---|---|
| `vault.json`, `account.json` (sync response, protected user key, KDF) | Unchanged: end-to-end EncStrings and the master-password-protected user key; directory ACL only | DPAPI would add nothing while the user key is required anyway, and would hurt troubleshooting. Disk theft is BitLocker's job; device encryption is on by default on many new 24H2 machines [i]. |
| Refresh token | `SealedFileStore` from `linux-support.md` §5.1 (HKDF of the user key, AES-256-GCM, one file per secret), wrapped in DPAPI | The user-key seal stops anyone without the master password. DPAPI adds machine and logon binding, so a copied disk plus a phished master password still cannot reach the API. |
| 2FA-remember token | DPAPI only | Only machine binding helps this token (Linux §5.1), and DPAPI provides it on every Windows. It is read before login, which DPAPI allows because it needs no user key. |
| Hello enrolment (`accounts/<id>/hello.bin`) | Bound to the Passport key (§3.2) | No extra layer needed. |
| `settings.json`, `browsers.json`, `device.json` | Directory ACL | Not secret. |

DPAPI calls: `CryptProtectData`/`CryptUnprotectData` in user scope with `CRYPTPROTECT_UI_FORBIDDEN`. Use entropy = a constant plus the
user id; it is public and only stops generic tools from decrypting. If an admin force-resets a local account's password, DPAPI keys
are lost and the user logs in again [i]; acceptable.

Same-user processes can still use the daemon's pipes while the vault is unlocked; nothing at rest changes that (as on Linux).

### 4.2 Location

`%LOCALAPPDATA%\Vaultkeeper`, through `ProjectDirs::data_local_dir()`. `paths.rs` uses `data_dir()` today, which on Windows is
**Roaming** AppData [v: `directories-6.0.0/src/win.rs`]; roaming profiles would copy tokens and the Hello file to machines where they are
useless or harmful.

### 4.3 Directory ACL

Set once on the data directory, inherited by everything inside:

```
D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;<user SID>)S:(ML;OICI;NRNWNX;;;ME)
```

- `P`: protected, so nothing is inherited from the parent.
- SYSTEM and Administrators stay. They bypass ACLs through privileges anyway, and removing them breaks Defender and backup, not
  attackers.
- The medium-integrity "no read up" label stops low-integrity and AppContainer processes (browser renderers, sandboxed apps) from
  reading. The default label only stops them from writing [i].
- Set `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED` on the directory, so Windows Search does not index the cache metadata.

The SDDL is applied with `ConvertStringSecurityDescriptorToSecurityDescriptorW` and `SetNamedSecurityInfoW` [i].

### 4.4 Startup checks (daemon and UI)

Counterpart of `linux-support.md` §5.4; `fs.rs` today only enforces modes under `cfg(unix)` [v].

- Open the directory with `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS`. **Refuse** if it is a reparse point
  (junction, symlink, mount point), if its owner is neither the user nor Administrators, or if any ACE grants a SID other than
  the user, SYSTEM and Administrators.
- **Repair** the DACL, label and attribute when the owner is right (restored backup, copied folder).
- Run the same checks on `account.json`, the token files and `hello.bin`.

### 4.5 Atomic writes

`write_private_atomic` keeps its shape: a temp file in the same directory, then a rename. On Windows the rename should be
`SetFileInformationByHandle(FileRenameInfoEx)` with `REPLACE_IF_EXISTS | POSIX_SEMANTICS`, which recent Rust `fs::rename` uses [i].
Not `ReplaceFileW`, which takes several steps and copes worse with antivirus. Open our own files with
`FILE_SHARE_READ | FILE_SHARE_DELETE`, and retry `ERROR_SHARING_VIOLATION` and `ERROR_ACCESS_DENIED` about five times with backoff,
because antivirus scans the fresh temp file [i]. The directory `sync_all` already tolerates failure, which it will get on Windows.

## 5. Process hardening and IPC

### 5.1 Process hardening

Windows lets any same-user process `OpenProcess` ours with read and write access by default. Hardening blocks the common
info-stealer that reads another process's memory. It does not stop a determined same-user attacker, who can start our exe suspended
and inject before hardening runs, or simply run their own copy. It is the Windows counterpart of `PR_SET_DUMPABLE`, not a boundary.

- **Process and thread DACL**, first thing in `main`: `D:P(A;;0x1000;;;<user SID>)(A;;RC;;;OW)`. 0x1000 is
  `PROCESS_QUERY_LIMITED_INFORMATION`, which Task Manager and the pipe checks need. The OWNER RIGHTS ACE removes the owner's
  implicit `WRITE_DAC`, so the DACL cannot simply be loosened again [i]. Bitwarden does the same through the `secmem-proc` crate
  [v: `core/src/process_isolation/windows.rs`].
- **UI spawned hardened.** The daemon passes the same security descriptor in `CreateProcess`'s `lpProcessAttributes` and
  `lpThreadAttributes`, plus `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` in `STARTUPINFOEX`. The UI is then protected before its first
  instruction, and the daemon keeps full access through its creation handle [i].
- **Mitigation policies.**
  - Daemon: `ExtensionPointDisable`, image load `NoRemoteImages | NoLowMandatoryLabelImages | PreferSystem32Images`,
    `ProhibitDynamicCode` (no JIT in Rust or Slint), `StrictHandleCheck`, `MicrosoftSignedOnly`. The last one blocks antivirus
    products that inject user-mode hooks, so test with Defender and two third-party products.
  - UI: the same minus `MicrosoftSignedOnly`, because `IFileDialog` loads third-party shell extensions (OneDrive, Dropbox,
    TortoiseGit). `ExtensionPointDisable` turns off legacy IMEs; test CJK input [i].
- **Loader and linker.**
  - `/DEPENDENTLOADFLAG:0x800` (`LOAD_LIBRARY_SEARCH_SYSTEM32`) for static imports: free, and it closes DLL planting next to a
    per-user exe. Add `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` first thing for runtime loads.
  - `+crt-static`, because `vcruntime140.dll` is not a KnownDLL.
  - `-C control-flow-guard`, and `/CETCOMPAT` on x64.
- **Crash dumps.** `panic = "abort"` already; Windows Error Reporting can still write dumps if LocalDumps is configured.
  `WerRegisterExcludedMemoryBlock` around secure-memory pages is an option [i].

### 5.2 UI channel: no pipe name at all

The daemon creates a GUID-named pipe (`FILE_FLAG_FIRST_PIPE_INSTANCE`, one instance, DACL as in §5.3) and opens the client end
itself. It passes that handle to the UI through `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` plus a command-line argument, and the UI wraps
it with `NamedPipeClient::from_raw_handle` [i]. The daemon created the server end, so nobody can squat the name. Pipe names can be
listed, though, so another same-user process could connect in the gap between creating the pipe and opening the client end.
Close that with one check before handing the handle down: `GetNamedPipeClientProcessId` on the server end must be the daemon's own
pid. After that neither side needs a peer check. This is the Windows form of "the UI is spawned by the daemon". It matters because
the UI sends the master password.

### 5.3 CLI and browser-host pipes

These clients are started by others (a terminal, the browser), so they need named pipes:
`\\.\pipe\vaultkeeper.<user SID>.cli` and `….browser`. The pipe namespace is machine-wide, so the SID keeps another user from
pre-creating our name, and the single-instance lock allows one daemon per user.

- First instance with `FILE_FLAG_FIRST_PIPE_INSTANCE`. `ERROR_ACCESS_DENIED` means someone squatted the name: refuse with a clear
  message, and never fall back to another name.
- `PIPE_REJECT_REMOTE_CLIENTS`.
- DACL `D:P(A;;0x12019b;;;<user SID>)(A;;RC;;;OW)`: generic read and write **minus** `FILE_CREATE_PIPE_INSTANCE` (0x4). With plain
  `GENERIC_WRITE`, any same-user process could add an instance and receive the next client. That denies our own user new instances
  too, so pre-create a small pool at start and recycle instances with disconnect/connect, or tighten the DACL with
  `SetSecurityInfo` once the pool exists [i].
- The client checks the server: `GetNamedPipeServerProcessId`, then the image path and `FILE_ID_INFO` (volume serial plus
  128-bit file id) must equal our own exe's. The CLI's TLS does not add server authentication: the daemon generates its key in
  memory and sends the certificate over the same socket before the handshake [v: `crates/ipc/src/cli_access.rs`], so a squatter
  would send its own. A squatting server could only feed the CLI false answers; the CLI sends no secrets.
- The daemon checks the client: `GetNamedPipeClientProcessId` → `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` →
  `QueryFullProcessImageNameW`, then the same `FILE_ID_INFO` comparison, plus `GetNamedPipeClientSessionId` equal to ours. Not
  Authenticode: it would admit any build signed with our certificate, the objection the architecture doc raises against a designated
  requirement.

**Status:** a mistake guard, as on Linux (`linux-support.md` §7.6). A same-user attacker can inject into the real binary. The
cdhash-based guarantee from macOS does not carry over.

## 6. Single instance

Today: `flock` on `instance.lock` plus a Unix socket [v: `single_instance.rs`]. On Windows: a named mutex
`Local\Vaultkeeper-<user SID>` decides who is first. The kernel releases it when the process dies. Later launches send their one command
over a SID-named pipe built as in §5.3 [i].

## 7. Other platform pieces

### 7.1 Tray

Slint 1.18 has a Windows tray backend using `Shell_NotifyIconW` directly, with menus and re-adding the icon after
`TaskbarCreated` [v: `i-slint-core-1.18.1/items/system_tray/windows.rs`]. Windows 11 puts new icons in the overflow flyout until the
user pins them (Settings → Personalization → Taskbar → Other system tray icons) [i]. Say so on first run.

**Icon style: default Blue, with Auto, White and Black as options.**

- Windows has no template-image mechanism, so the shell never recolours a tray icon. Most third-party tray icons are in
  colour, while Windows' own (network, volume, OneDrive) are monochrome and follow the taskbar [i]. Both look native.
- Blue reads on both the light and the dark taskbar. It also matches the Start menu, taskbar and installer icon, which helps
  people find it in the overflow flyout.
- Blue fails in one common setup: "Show accent colour on Start and taskbar" with a blue accent, and Windows' default accent
  is blue [i]. White and Black cover that case, and suit people who want the monochrome system look.
- Auto picks White or Black from the **taskbar** theme: `SystemUsesLightTheme` under
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, which is separate from the apps' `AppsUseLightTheme`. An
  accent-coloured taskbar exists only in dark mode, so it gets White [i]. In High Contrast mode, follow the contrast theme.
- Watch for changes with `RegNotifyChangeKeyValue` on that key. A `WM_SETTINGCHANGE` "ImmersiveColorSet" handler would need a
  window, and the tray process must stay windowless (see the comment in `app/ui/tray.slint`).
- One setting for all platforms: extend today's "Menu bar icon: Auto / White / Black" (`ThemeChoice`) to a tray style with
  `Blue` added. Defaults: Blue on Windows, Auto on macOS (template-style convention); `linux-support.md` §4 proposes the same
  four choices for Linux. Label it "Tray icon" on Windows.
- The blue glyph is not the app icon shrunk down: the white tile and gradient turn to mush at 16 px. Use the tray shield
  shape in flat `#2F6BEA` with the keyhole **filled white** instead of cut out, so it reads on any background.
- Size: Slint rasterises the image once with `to_rgba8()` at the SVG's intrinsic size (the tray SVGs are 36×36) and builds the
  HICON from that [v: `create_hicon`]. Windows then scales it to 16/20/24/32 px by DPI [i], which blurs the keyhole. Ship
  pixel-tuned variants, or rasterise at `GetSystemMetricsForDpi(SM_CXSMICON)` and pass `Image::from_rgba8`.

### 7.2 Global hotkey and focus

`global-hotkey` 0.9 has a Windows backend (`RegisterHotKey`) [v: `platform_impl/windows`]. The ⌘⇧Space default has no
direct equivalent, and Windows reserves many Win+ chords, so pick a Ctrl+Shift or Ctrl+Alt chord. Avoid Ctrl+Alt on layouts
where it equals AltGr [i].

Focus: Windows lets a process take the foreground only if it received the last input or was allowed by the foreground
process. The daemon receives `WM_HOTKEY` (or the tray click), so it holds that right. It must call
`AllowSetForegroundWindow(ui_pid)` before telling the UI process to show the Quick Panel [i]. Unlike Wayland, the panel can be
positioned (monitor under the cursor via `MonitorFromPoint`), and hide-on-focus-loss works.

### 7.3 Lock, sleep, network

Bitwarden has no Windows power monitor (`core/src/powermonitor` has only Linux and a stub) [v]. Use
`WTSRegisterSessionNotification` → `WM_WTSSESSION_CHANGE` / `WTS_SESSION_LOCK` for screen lock, and
`PowerRegisterSuspendResumeNotification` for sleep [i]. Most Windows 11 laptops use Modern Standby, where "sleep" is screen off
plus the session lock, so lock-on-screen-lock covers it [i]. Network changes: `NotifyNetworkConnectivityHintChange`, or keep
only the existing `/alive` probe [i]. Logoff and shutdown: the daemon gets `WM_QUERYENDSESSION`/`WM_ENDSESSION` (or a console
control handler) instead of SIGTERM, and must lock and flush there [i].

### 7.4 Clipboard

`arboard` 3.7's Windows backend can register the formats `ExcludeClipboardContentFromMonitorProcessing`,
`CanUploadToCloudClipboard` = 0 and `CanIncludeInClipboardHistory` = 0 [v: `arboard-3.7.0/src/platform/windows.rs`]. Turn on all three
for secrets: otherwise Win+V history keeps them and the cloud clipboard syncs them to other devices, which macOS has no counterpart
for. The daemon has no window, which is fine on Windows: `OpenClipboard(NULL)` works without one [i]. The existing auto-clear rule
(SHA-256 of the last value) carries over unchanged.

### 7.5 Auto-type

`SendInput` with `KEYEVENTF_UNICODE` down/up pairs and a check that the inserted count matches [v: Bitwarden]. Remember
`GetForegroundWindow()` before the Quick Panel opens and bring that window back before typing. Wait for the hotkey's modifiers
to be released, as on the other platforms. UIPI blocks input into elevated windows; detect this (`SendInput` returns 0) and say
so [i]. The secure desktop (UAC, Ctrl+Alt+Del) is unreachable by design.

### 7.6 Autostart

See §1: `auto-launch` covers the Run key and the StartupApproved state [v]. The command is `"…\vaultkeeper.exe" --tray`.

### 7.7 Paths

See §4.2: `data_local_dir()` instead of `data_dir()`.

### 7.8 Browser native messaging

- Registration is per user in the registry (`HKCU\Software\Google\Chrome\NativeMessagingHosts\<name>`, the Edge, Brave and
  Chromium equivalents, `HKCU\Software\Mozilla\NativeMessagingHosts\<name>`), each pointing to a manifest file [i].
- Chromium browsers start the host **through `cmd.exe`** unless the `NativeHostsExecutablesLaunchDirectly` policy is set
  (Chrome/Edge 120+) [v: Chrome Enterprise policy page]. `browser_host/parent.rs` assumes the browser is the direct parent; on
  Windows the parent can be `cmd.exe` and the browser its parent [i].
- The macOS host identifies the browser by its code-signing requirement (Team ID). On Windows the equivalent is an
  Authenticode check of the parent's image (`WinVerifyTrust` plus the signer subject: Google LLC, Microsoft Corporation,
  Mozilla Corporation, Brave Software) [i].

### 7.9 Security keys (2FA login)

`app/src/os/security_key.rs` uses Mozilla's `authenticator` crate over raw USB HID. The crate has a Windows HID transport
[v: `authenticator-0.5.0/src/transport/windows`], but since Windows 10 1903 non-elevated apps are expected to use the
Windows WebAuthn API (`webauthn.dll`) instead of raw FIDO HID [i: the Yubico technical manual says so, but the quote was cut
off]. Bitwarden's `win_webauthn` crate (GPL, Rust, wraps the November 2025 `webauthn.dll` API) is a ready base [v]. Windows then
draws the PIN and touch UI itself, so the login window shows only "Follow the Windows prompt".

### 7.10 SSH agent

The vendored listener works as-is for OpenSSH's `ssh.exe` [v]. Patch it (and record it in `vendor/PATCHES.md`):
- create the first instance with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so we never join a pipe someone else created; otherwise the
  instances of two agents are served in turn and `ssh` reaches the wrong one at random;
- an explicit DACL as in §5.3, plus `PIPE_REJECT_REMOTE_CLIENTS`;
- if creation fails because the name exists, say "the Windows OpenSSH Authentication Agent service is running; stop and
  disable it, or turn off Vaultkeeper's agent".

The peer is `ssh.exe`; its pid and process name are for the approval window only. Document two known gaps: Git for Windows'
bundled `ssh` does not use the pipe (set `core.sshCommand = C:/Windows/System32/OpenSSH/ssh.exe`), and WSL needs a relay such as
`npiperelay` [i]. `peer_info.rs` has macOS-only branches; on Windows the process name comes from the pid via `sysinfo` [v].

### 7.11 CLI and the console

A GUI-subsystem exe cannot print to the terminal that started it, and a console-subsystem exe flashes a console window
when started from Explorer or autostart. On 24H2+ the answer is one console-subsystem binary with
`<consoleAllocationPolicy>detached</consoleAllocationPolicy>` in its manifest: no console is allocated when it is launched from
the GUI, and the shell waits for it as for any console app [v: Microsoft Learn]. Whether it shares the parent terminal's console
automatically or must call `AttachConsole(ATTACH_PARENT_PROCESS)` is not stated; test it [i]. Piped use
(`vaultkeeper get … | cmd`) works either way, because redirected std handles are inherited [i]. The installer adds the install
directory to the user `PATH` (`HKCU\Environment`) [i].

Shells wait for console-subsystem programs, and a process attached to a terminal dies when that terminal closes. So `vaultkeeper` or
`vaultkeeper --tray` run from a terminal, and the browser host when it starts the daemon (`browser_host/mod.rs` uses
`open -g -a` on macOS [v]), must start the daemon as a separate process with no console (`DETACHED_PROCESS`, a new process group,
and `CREATE_BREAKAWAY_FROM_JOB` when started by the browser) and then return [i].

### 7.12 Smaller items

- Recall and screen capture: `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` on the Quick Panel and any window showing a
  revealed secret keeps them out of Recall snapshots on Copilot+ PCs. It also blacks them out in screen sharing, so make it a
  setting [i].
- Application manifest via `embed-resource` or similar: PerMonitorV2 DPI awareness, Common Controls v6 (for file dialogs),
  UTF-8 active code page, `supportedOS` for Windows 10/11, the console policy above [i].
- `rfd` is a macOS-only dependency today; add it for Windows (`IFileDialog`) [v: `app/Cargo.toml`].
- `fs::swap` (used by the updater) is macOS-only. On Windows a running exe can be renamed but not overwritten (§8.3) [i].
- Re-measure memory: the software renderer and a tray-only daemon should behave as on macOS, but GDI and WinRT add their
  own allocations [i].

## 8. Packaging, signing and updates

### 8.1 Install model

Default **per-user**: `%LOCALAPPDATA%\Programs\Vaultkeeper`, self-update without UAC. A per-machine install in Program Files
would only stop same-user code from replacing the exe for good, and that attacker already wins through §5. A privileged
updater service would add more attack surface than it removes. Optionally also ship a per-machine MSI with self-update
turned off, updated through `winget`.

Not the Store's MSIX for now. It virtualizes HKCU registry writes, which breaks the `NativeMessagingHosts` keys unless registry
write virtualization is disabled [i]. It also replaces our updater and adds Store review cadence.

### 8.2 Signing

As of 2026-11-10 [v: Microsoft Learn "Code signing options"]:

| Option | Cost | Who | SmartScreen / Smart App Control |
|---|---|---|---|
| Microsoft Store, MSIX | Free (Microsoft re-signs) | Worldwide | No warnings |
| SignPath Foundation | Free OV-level signing for qualifying open-source projects | OSS | Trusted signature; reputation builds over time [i] |
| Azure Artifact Signing | ~$9.99/month | Organizations: US, Canada, EU, UK; individuals: US and Canada only | Reputation builds over time |
| OV certificate | $150–300/year, key on an HSM or token | Worldwide | Same as Artifact Signing |
| Self-signed | Free | — | Blocked for public users |

Recommendation: SignPath Foundation. Its key sits in their HSM and it builds from the public repo, a better trust story than
today's key in the maintainer's keychain and the CI secrets. An OV certificate is the fallback. Expect "unknown publisher"
warnings on the first releases even when signed; reputation builds up. Check which publisher name users see under SignPath's
open-source program (theirs or the project's) [i]; it decides what SmartScreen reputation attaches to.

### 8.3 Update trust

- The primary anchor is an **Ed25519 (minisign-style) key embedded in the binary**, shared with the Linux plan. It survives a change
  of signing certificate, which the README calls a reinstall-by-hand event on macOS. Rotate it by shipping a "next key" signed by
  the old one.
- Also require a valid Authenticode chain, so Smart App Control accepts the installed binary, but do not pin the publisher.
- Install: download, verify, rename the running exe aside (Windows allows that), move the new one in, restart the daemon, and
  delete the old file on the next start [i].

## 9. ARM64

- Toolchain: `aarch64-pc-windows-msvc` became Tier 1 in Rust 1.91 (2025-10-30) [v]. The repo pins 1.99.1.
- CI: `windows-11-arm` hosted runners are GA for public repositories since 2025-08-07 [v].
- Native code: `cargo tree --target aarch64-pc-windows-msvc` shows `aws-lc-sys` (via `aws-lc-rs`, used by `rustls` for
  `reqwest`, the websocket and the CLI's TLS, and by `rcgen`) as the only crate that builds C [v]. On ARM64 it needs clang-cl
  ("C++ Clang Compiler for Windows" in the VS Build Tools). On x64 it needs NASM or its `prebuilt-nasm` objects [v: aws-lc-rs
  docs]. Everything else is Rust or `windows`/`windows-sys`/`winapi` bindings [v].
- An x64 build runs on ARM64 Windows 11 under emulation, so x64 can ship first [i].
- Hello, `webauthn.dll` and named pipes have no architecture-specific code paths [i]. Still test Hello on a Snapdragon machine
  (face and fingerprint drivers differ). `/CETCOMPAT` is x64-only.
- Release work: a second job, a second installer (or one installer carrying both), signing both, and a per-arch asset name the
  updater picks.

## 10. Open risks and decisions

Risks to check on real machines (a Hello spike first, like step 0b of the architecture plan):

1. Passport KSP: the key name format, OAEP support, the one-time prompt at creation, a window owned by another process as
   `NCRYPT_WINDOW_HANDLE_PROPERTY`, the gesture-required property, face unlock without `0x80098044` after the foreground hand-off.
2. Hello after a PIN reset, after removing Hello, over RDP, and in a VM without a TPM.
3. `MicrosoftSignedOnly` in the daemon against antivirus hooks; `ProhibitDynamicCode` and `ExtensionPointDisable` in the UI with
   CJK IMEs and the file dialog.
4. The pipe pool when the DACL withholds `FILE_CREATE_PIPE_INSTANCE`; handing the UI its pipe end through `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`.
5. The detached console policy in cmd, PowerShell and Windows Terminal, interactive and piped.
6. Chromium's `cmd.exe` parent and the Authenticode browser check; Firefox's direct launch.
7. 2FA security keys through `webauthn.dll`.
8. Tray icon sharpness at 100–200 % scaling.
9. Run the Hello spike and the tray **with full hardening on** (process DACL and mitigation policies): the credential broker and
   accessibility tools talk to our processes.
10. Screen readers (Narrator, NVDA) against `ExtensionPointDisable` in the UI. Slint's `accessibility` feature is on, and NVDA uses hooks.
11. A daemon started by the browser host survives the host's exit (Chromium may run hosts in a kill-on-close job object).

Open decisions:

1. Signing route: apply to SignPath Foundation, or buy an OV certificate.
2. Default Quick Panel hotkey on Windows.
3. Ship a per-machine MSI next to the per-user installer, or not.
4. Whether capture exclusion (Recall) is on by default.

Decided: floor Windows 11 24H2. Proposed, waiting for the spike: Hello through the Passport KSP (§3.2); tray default Blue (§7.1).

## 11. Effort estimate (one developer, rough)

| Block | Weeks |
|---|---|
| Platform traits, no behaviour change (README phase 1, shared with Linux) | 1–2 |
| Windows bring-up: build, CI, manifest, Local AppData, ACLs and startup checks, hardening | 1.5–2 |
| IPC over pipes (inherited UI channel, CLI, browser, single instance) with checks | 1.5–2 |
| Tray, hotkey, focus hand-off, Quick Panel placement | 1–1.5 |
| Clipboard exclusions, lock/sleep/network events | 0.5–1 |
| Token store (sealed files + DPAPI) | 0.5–1 |
| **MVP total** (vault, Quick Panel, tray, clipboard, SSH, CLI; signed installer; no Hello, auto-type, security keys, updater) | **6–9** |
| Windows Hello: spike, enrol, unlock, SSH approval, focus, UI relabel | 2–2.5 |
| Auto-type | 1 |
| Security keys via `webauthn.dll` | 1–1.5 |
| Browser native messaging (registry, `cmd.exe` parent, Authenticode browser check) | 1 |
| SSH agent pipe patch and docs | 0.5 |
| Installer, signing pipeline, self-updater | 1.5–2 |
| ARM64 | 0.5 |
| Test pass on real hardware (Intel/AMD and Snapdragon, face and fingerprint) + fixes | 1–1.5 |
| **Parity total** | **15–20** |

## Sources

- Code: `crates/platform/src/{biometric.rs,biometric/envelope.rs,keychain.rs,fs.rs,hardening.rs,paths.rs,single_instance.rs}`,
  `crates/ipc/src/{peer.rs,cli_access.rs}`, `crates/vault/src/{secrets.rs,store.rs}`, `app/src/os/{layout.rs,security_key.rs,biometrics.rs}`,
  `app/src/browser_host/parent.rs`, `app/src/daemon/tray.rs`, `app/ui/tray.slint`, `app/Cargo.toml`,
  `vendor/ssh_agent/src/server/listener/windows.rs`, `vendor/secure_memory/src/secure_key/dpapi.rs`.
- Crates: `i-slint-core-1.18.1/items/system_tray/windows.rs`, `arboard-3.7.0/src/platform/windows.rs`, `directories-6.0.0/src/win.rs`,
  `auto-launch-0.6.0/src/windows.rs`, `global-hotkey-0.9.0/src/platform_impl/windows`, `authenticator-0.5.0/src/transport/windows`,
  `windows-0.62.2` (KeyCredential and `IUserConsentVerifierInterop` bindings); `cargo tree --target {x86_64,aarch64}-pc-windows-msvc`.
- Bitwarden desktop_native (local `../clients`): `biometric/src/{windows.rs,encryption.rs,windows_focus.rs}`,
  `core/src/process_isolation/windows.rs`, `core/src/password/windows.rs`, `core/src/powermonitor`, `autotype/src/type_input/windows.rs`,
  `win_webauthn/README.md`.
- KeePassXC `src/quickunlock/WindowsHello.cpp` (develop); KeePassWinHello issue #120 and PR #159 (`WINBIO_E_INVALID_TICKET`).
- Microsoft Learn: KeyCredentialManager, KeyCredential, KeyCredentialCacheConfiguration and RequestDeriveSharedSecretAsync
  (winrt-28000 view); Console Allocation Policy; Code signing options (2026-11-10); Smart App Control FAQ; Windows 11 Home/Pro and
  Enterprise/Education lifecycle.
- WindowsAppSDK issue #4290 (Hello prompt parenting for Win32, fix committed 2025-07).
- Rust 1.91.0 release notes; GitHub changelog 2025-08-07 (arm64 runners GA); aws-lc-rs Windows requirements.
- Chrome Enterprise policy `NativeHostsExecutablesLaunchDirectly`.
- Security design review (Fable): §3.2–§3.4, §4, §5, §8.
