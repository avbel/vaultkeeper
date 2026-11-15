# Windows 11 support (24H2+, x64 only)
Design source: docs/solutions/windows-support.md (§ numbers below point there). User request: "Lets add Windows support (only Win11 24h2+)", x64 only, full parity in phases, Inno Setup per-user installer, optional code signing, winget built and published from CI, follow the rust-high-performance skill.
Conventions for every step:
- No behaviour change on macOS. Every step that touches shared code also runs the macOS checks of the crates it touched.
- Windows code lives in `#[cfg(windows)]` modules (`windows.rs` or a `windows/` dir). Keep anything that can be portable (SDDL strings, pipe names, envelope encoding, manifest generation, asset selection) portable and unit-tested on macOS.
- Win32 through `windows-sys` 0.61 (already in Cargo.lock); `windows` 0.62 only for WinRT and the vendored ssh_agent. Every `unsafe` block gets a `// SAFETY:` comment. Close handles with an owning wrapper (`OwnedHandle` or a small Drop type), never by hand on each path.
- Comments explain why, never what. Workspace clippy is pedantic with `-D warnings`; `unwrap` is denied.
- Windows check on this Mac: `scripts/check-windows.sh -p <crate> --all-targets` (cargo-xwin clippy, created in step 0a). Windows tests run in CI (step 0c), not locally.
- Performance (rust-high-performance): no `target-cpu=native`, no allocator swap without measurement, reuse frame buffers, prefer `windows-sys` over `windows` for compile time and size.
- Reuse existing code as much as possible (user request). Extend the existing seams (`Hooks` traits in app/src/hooks.rs, `SecretStore`, `ClipboardBackend`, `KeyAgreement`/envelope, `PeerVerifier`, frame.rs, `write_private_atomic`, the non-macOS fallbacks) instead of adding parallel ones. Prefer crates already in Cargo.lock (tokio named pipes, arboard's Windows options, auto-launch, global-hotkey, Slint's tray, sysinfo, `windows`/`windows-sys`, the vendored ssh_agent Windows listener). Port from Bitwarden's GPL desktop_native in ../clients/apps/desktop/desktop_native (same license; note the source file in a comment) before writing from scratch: `process_isolation/` and `core/src/process_isolation/windows.rs` (process DACL), `autotype/src/type_input/windows.rs` (SendInput), `win_webauthn/` (webauthn.dll), `biometric/src/windows.rs` (NCrypt/Hello glue, without its focus hacks). Write new code only where nothing fits.
- Phase gate (orchestrator, before every phase commit and again before 8a): the full macOS suite, `scripts/check.sh && CARGO_TARGET_DIR=target/lean cargo test --workspace`, must pass. If IPC tests time out for no visible reason, count the files in target/debug/deps first (a huge count slows the macOS peer code-identity check).
- Never edit README.md (it has the user's uncommitted edits). Vendored code changes are recorded in vendor/PATCHES.md.
- Hardware-only behaviour (Hello, hardening against AV/IME, installer) is verified by the user on a Win11 PC from docs/solutions/windows-test-checklist.md (step 7a); a step marked `gate:` must not be built on until the user reports the result.

## 0a Windows cross-check script and target flags
files: scripts/check-windows.sh, .cargo/config.toml
do: - `scripts/check-windows.sh [cargo args]`: POSIX sh, `set -e`, prepends `/opt/homebrew/opt/llvm/bin:/opt/homebrew/opt/lld/bin` to PATH, sets `CARGO_TARGET_DIR` to `${VK_XWIN_TARGET_DIR:-$HOME/Library/Caches/vaultkeeper-xwin}` unless already set, runs `cargo xwin clippy --target x86_64-pc-windows-msvc "$@" -- -D warnings`. Fails with a clear message if cargo-xwin is missing.
  - `.cargo/config.toml` with `[target.x86_64-pc-windows-msvc] rustflags` = `+crt-static` (vcruntime is not a KnownDLL, §5.1), `-C control-flow-guard`, `-C target-cpu=x86-64-v2` (24H2 requires SSE4.2 and POPCNT, so this baseline is free), `-C link-arg=/DEPENDENTLOADFLAG:0x800`, `-C link-arg=/CETCOMPAT`. Nothing for other targets.
done-when: `sh -n scripts/check-windows.sh`; `scripts/check-windows.sh -p vk-crypto --all-targets`; `cargo check -p vk-crypto`
difficulty: easy
kind: change

## 0b Windows warnings in vk-platform
files: crates/platform/src/
do: `scripts/check-windows.sh -p vk-platform --all-targets` reports unused `DIR_MODE`/`FILE_MODE` in fs.rs, an unused import in paths.rs tests and unused `code`/`from_code` in single_instance.rs. Gate them with the right `cfg` so the Windows build is warning-free; do not delete code macOS uses.
done-when: `scripts/check-windows.sh -p vk-platform --all-targets`; `cargo clippy -p vk-platform --all-targets -- -D warnings`
needs: 0a
difficulty: easy
kind: change

## 0c CI workflow for macOS and Windows
files: .github/workflows/ci.yml, .github/workflows/cargo-cache.yml
do: - New `ci.yml`: on push to main and windows-support, pull_request and workflow_dispatch; `permissions: contents: read`; concurrency cancels superseded runs.
  - Job `macos` (macos-latest): `scripts/check.sh` then `cargo test --workspace`.
  - Job `windows` (windows-latest): env `AWS_LC_SYS_PREBUILT_NASM=1`; `rustup show active-toolchain || rustup toolchain install`; Swatinem/rust-cache@v2 with `shared-key: windows-ci`; then clippy `-D warnings` and `cargo test` over the packages listed in a job-level env `WINDOWS_PACKAGES` (start with `-p vk-crypto -p vk-gen -p vk-api -p vk-vault -p vk-platform -p vk-webauthn -p secure_memory -p ssh_agent`). Later steps extend that list; step 3o replaces it with `--workspace`.
  - `cargo-cache.yml`: add a second job `windows-deps` on windows-latest that cooks release dependencies for `-p vaultkeeper --target x86_64-pc-windows-msvc` with shared key `windows-release`, mirroring the macOS job's cargo-chef steps and comments.
done-when: `ruby -ryaml -e 'YAML.load_file(".github/workflows/ci.yml"); YAML.load_file(".github/workflows/cargo-cache.yml")'`; jobs macos and windows exist in ci.yml
needs: 0a, 0b
difficulty: easy
kind: change

## 1a vk-win crate: SIDs, SDDL and owned handles
files: crates/win/, Cargo.toml
do: - New workspace member `crates/win`, package `vk-win`, description "Windows security helpers shared by vk-platform, vk-ipc and vk-ssh". Compiles on every target; Windows code under `cfg(windows)`.
  - Portable (tested on macOS): `sddl::private_dir(sid) -> String` = `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;<sid>)S:(ML;OICI;NRNWNX;;;ME)` (§4.3); `sddl::pipe(sid)` = `D:P(A;;0x12019b;;;<sid>)(A;;RC;;;OW)` (§5.3, read/write without FILE_CREATE_PIPE_INSTANCE); `sddl::process(sid)` = `D:P(A;;0x101000;;;<sid>)(A;;RC;;;OW)` (PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, so Task Manager, the pipe checks and `wait_for_exit` keep working, §5.1); `sddl::thread(sid)` = `D:P(A;;0x100800;;;<sid>)(A;;RC;;;OW)` (THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE; 0x1000 on a thread is THREAD_RESUME, so the process mask must not be reused); `sddl::mutex(sid)` = `D:P(A;;0x1F0001;;;<sid>)`. Validate that `sid` matches `S-1-(\d+-)+\d+` and return an error otherwise, so a malformed SID can never widen a DACL.
  - Windows: `current_user_sid() -> io::Result<String>` (GetTokenInformation TokenUser + ConvertSidToStringSidW); `SecurityDescriptor::from_sddl(&str)` owning the LocalAlloc'd descriptor (ConvertStringSecurityDescriptorToSecurityDescriptorW, LocalFree on Drop) with `as_attributes(inherit: bool) -> SECURITY_ATTRIBUTES`; `current_session_id()`.
  - Add `windows-sys = { version = "0.61.2", features = [...] }` to the root `[workspace.dependencies]` once, with the union of features the whole plan needs, so parallel steps never edit features (cargo unifies them anyway, so there is no extra compile cost): Win32_Foundation, Win32_Security, Win32_Security_Authorization, Win32_Security_Cryptography, Win32_Security_WinTrust, Win32_Storage_FileSystem, Win32_System_Pipes, Win32_System_Threading, Win32_System_IO, Win32_System_Memory, Win32_System_Console, Win32_System_LibraryLoader, Win32_System_Registry, Win32_System_RemoteDesktop, Win32_System_Power, Win32_System_SystemServices, Win32_System_Diagnostics_ToolHelp, Win32_System_DataExchange, Win32_System_Com, Win32_UI_WindowsAndMessaging, Win32_UI_Input_KeyboardAndMouse, Win32_UI_HiDpi, Win32_UI_Shell, Win32_Graphics_Gdi, Win32_Graphics_Dwm, Win32_NetworkManagement_IpHelper, Win32_Networking_WinSock, Win32_Networking_WindowsWebServices. Crates then use `[target.'cfg(windows)'.dependencies] windows-sys.workspace = true`; a missing feature is added only in the root list.
done-when: `cargo test -p vk-win`; `cargo clippy -p vk-win --all-targets -- -D warnings`; `scripts/check-windows.sh -p vk-win --all-targets`
deps: windows-sys@0.61
needs: 0a
difficulty: medium
kind: change

## 1b vk-win: executable identity of a process
files: crates/win/
do: - Windows: `ImageIdentity { volume_serial: u64, file_id: [u8; 16] }` read with GetFileInformationByHandleEx(FileIdInfo) on a handle opened with FILE_READ_ATTRIBUTES and share-all flags; `ImageIdentity::of_current_exe()`, computed once on first use and cached in a `OnceLock` (callers must call it at startup), so renaming the running exe aside and planting another file at its path cannot change our own identity; `ImageIdentity::of_pid(pid)` via OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) + QueryFullProcessImageNameW, then open that path. `process_session_id(pid)` via ProcessIdToSessionId.
  - This is the Windows replacement for the macOS cdhash check (§5.3): same file on the same volume, not Authenticode.
  - Portable: the struct and `PartialEq`, so callers compile everywhere.
done-when: `cargo test -p vk-win`; `scripts/check-windows.sh -p vk-win --all-targets`
needs: 1a
difficulty: medium
kind: change

## 1c vk-ipc transport seam (Unix implementation only)
files: crates/ipc/src/transport.rs, crates/ipc/src/transport/, crates/ipc/src/lib.rs, crates/ipc/src/peer.rs
do: - Add `transport` with `Endpoint` (a socket path on Unix, a pipe name on Windows), `Listener::bind(&Endpoint)`, `Listener::accept() -> (Stream, PeerCredentials)`, `connect(&Endpoint) -> Stream`, where `Stream` implements tokio AsyncRead + AsyncWrite + Unpin + Send and can be split into owned halves.
  - Unix module wraps today's tokio UnixListener/UnixStream and moves credential reading out of peer.rs (`credentials(&UnixStream)`) behind accept. `PeerCredentials` keeps its fields on Unix; add `#[cfg(windows)]` fields `pid: u32, session_id: u32` later (step 2c) without changing Unix code.
  - Windows module: types that compile and return `io::ErrorKind::Unsupported` (filled in by 2a–2c).
  - Do not migrate any caller yet; existing tests must still pass.
done-when: `cargo test -p vk-ipc`; `cargo clippy -p vk-ipc --all-targets -- -D warnings`
needs: 0a
difficulty: medium
kind: change

## 1d vk-ipc: UI server on the transport
files: crates/ipc/src/server/
do: Replace UnixListener/UnixStream in server/mod.rs, connection.rs and dispatch.rs with `transport::{Listener, Stream}` and the credentials from `accept`. Keep `ServerHandle::path()` working on Unix (return the endpoint). Reuse one frame buffer per connection, as today.
done-when: `cargo test -p vk-ipc`; `cargo clippy -p vk-ipc --all-targets -- -D warnings`
needs: 1c
difficulty: medium
kind: change

## 1e vk-ipc: UI client on the transport
files: crates/ipc/src/client/
do: `RemoteVault::connect` takes an `Endpoint` (keep a path-based convenience on Unix so app/ callers still compile) and uses `transport::connect`; io.rs and service.rs drop `std::os::unix`. Add `RemoteVault::from_stream(Stream)` for the inherited Windows pipe (step 2e).
done-when: `cargo test -p vk-ipc`; `cargo clippy -p vk-ipc --all-targets -- -D warnings`; `cargo check -p vaultkeeper`
needs: 1d
difficulty: medium
kind: change

## 1f vk-ipc: CLI access and browser server on the transport
files: crates/ipc/src/cli_access.rs, crates/ipc/src/browser/
do: Move `cli_access::{serve, call, verify}` and `browser::server` from tokio Unix types to `transport`. The CLI's in-band TLS stays as is.
done-when: `cargo test -p vk-ipc`; `cargo clippy -p vk-ipc --all-targets -- -D warnings`; `cargo check -p vaultkeeper`
needs: 1e
difficulty: medium
kind: change

## 1g vk-ipc compiles on Windows
files: crates/ipc/
do: Remove the `compile_error!` for non-Unix targets in lib.rs, gate the remaining Unix-only code (peer.rs helpers such as `own_uid`, `parent_pid`, tests using `UnixStream::pair`) with cfg, and give non-macOS `SameExecutable` a Windows variant holding `vk_win::ImageIdentity` (verification itself comes in 2c).
done-when: `scripts/check-windows.sh -p vk-ipc --all-targets`; `cargo test -p vk-ipc`; `cargo clippy -p vk-ipc --all-targets -- -D warnings`
needs: 1f, 1b
difficulty: medium
kind: change

## 1h Endpoints and data directory per OS
files: crates/platform/src/paths.rs, app/src/os/layout.rs
do: - `paths::data_dir()` uses `ProjectDirs::data_local_dir()` on Windows (§4.2, not Roaming); macOS path unchanged.
  - layout.rs: socket names become endpoint constructors. Unix: files in the data dir as today. Windows: `\\.\pipe\vaultkeeper.<sid>.cli`, `….browser`, `….instance`, and the SSH agent's `\\.\pipe\openssh-ssh-agent`; the UI channel has no name (inherited, §5.2). Keep the pipe-name builder a portable pure function taking the SID string, with unit tests on macOS.
  - The vw-it Unix mode bits in layout.rs stay `cfg(unix)`.
done-when: `cargo test -p vk-platform paths`; `cargo test -p vaultkeeper layout`; `cargo clippy -p vk-platform -p vaultkeeper --all-targets -- -D warnings`
needs: 1g
difficulty: easy
kind: change

## 1i vk-ssh compiles on Windows
files: crates/ssh/
do: - Remove the Unix-only `compile_error!` in lib.rs. socket.rs keeps its Unix stale-socket logic under `cfg(unix)`; on Windows the agent endpoint is the pipe name and there is no file to clean up.
  - lib.rs `start_at` on Windows calls the vendored agent's Windows listener entry point (vendor/ssh_agent/src/server/listener/windows.rs) instead of the Unix one.
done-when: `scripts/check-windows.sh -p vk-ssh --all-targets`; `cargo test -p vk-ssh`; `cargo clippy -p vk-ssh --all-targets -- -D warnings`
needs: 1h
difficulty: medium
kind: change

## 1j App dependencies for Windows
files: app/Cargo.toml, app/src/os/security_key.rs, app/src/os/mod.rs
do: - `authenticator` (fails to build on Windows: libc vs winapi c_void) becomes `cfg(not(windows))`. On Windows `security_key.rs` returns the existing "unavailable" outcome until step 5c.
  - `rfd` is added for Windows with default features off (IFileDialog backend).
done-when: `cargo clippy -p vaultkeeper --all-targets -- -D warnings`; `cargo test -p vaultkeeper security_key`
needs: 1i
difficulty: easy
kind: change

## 1k The app compiles on Windows: app/src/os
files: app/src/os/
do: Run `scripts/check-windows.sh -p vaultkeeper --all-targets` and fix the errors and warnings inside app/src/os only, with `cfg` gates and Unsupported/no-op Windows stubs that mirror the existing non-macOS fallbacks (NoClipboard, Unavailable biometrics, Dock/CursorScreen no-ops). Replace `/usr/bin/open` in BrowserOpener with a cfg'd helper (ShellExecuteW "open" on Windows). Do not implement Windows features; leave a `// Windows: step <id>` marker at each stub the plan fills later. Errors in other directories are for 1n/1o.
done-when: no error from `scripts/check-windows.sh -p vaultkeeper --all-targets` points into app/src/os; `cargo clippy -p vaultkeeper --all-targets -- -D warnings`
needs: 1j
difficulty: medium
kind: change

## 1n The app compiles on Windows: app/src/daemon
files: app/src/daemon/
do: Same as 1k for app/src/daemon, including the updater's page opener (use the 1k helper) and the macOS-only updater toolchain calls (ditto, zipinfo, plutil, codesign), which become `cfg(target_os = "macos")` with a Windows stub returning "updates unavailable" until 5h.
done-when: no error from `scripts/check-windows.sh -p vaultkeeper --all-targets` points into app/src/daemon; `cargo test -p vaultkeeper update`
needs: 1k
difficulty: medium
kind: change

## 1o The app compiles on Windows: the rest
files: app/
do: Fix the remaining Windows errors and warnings outside app/src/os and app/src/daemon (browser_host, cli*, run.rs, main.rs, ui_process, app/src/app, tests, examples) the same way.
done-when: `scripts/check-windows.sh -p vaultkeeper --all-targets`; `scripts/check.sh`
needs: 1n
difficulty: medium
kind: change

## 1l Sealed token store (portable, shared with Linux)
files: crates/vault/src/sealed_store.rs, crates/vault/src/lib.rs, crates/vault/Cargo.toml
do: - `SealedFileStore` implementing `SecretStore` as in linux-support.md §5.1: `k = HKDF-SHA256(ikm = user key 64 bytes, salt = SHA-256(user_id), info = "vaultkeeper secrets v1")`; one file per secret `accounts/<user_id>/<name>.enc` = `"VKS1" ‖ version ‖ nonce[12] ‖ AES-256-GCM(k, nonce, aad = magic‖version‖name‖user_id)`; written with an injected atomic-write function.
  - Holds per-user keys in `Mutex<HashMap<String, Zeroizing<[u8; 32]>>>`, set with `provide_key(user_id, &user_key)` and dropped with `forget_key(user_id)`. Without a key, `get` returns a typed "locked" error, never `Ok(None)`, so a locked vault is not mistaken for a logged-out one.
  - An optional `BlobWrapper` trait (`wrap(&[u8]) -> Vec<u8>`, `unwrap`) applied outside the AES layer; DPAPI implements it on Windows (step 2g). A key-less mode for names that must be readable before login (the 2FA-remember token): wrapper only.
  - A GCM failure after a key was provided means the user key rotated elsewhere → typed `Undecryptable` error so callers log in again.
  - Key names stay the flat strings secrets.rs builds: split on the first `.`; `<user_id>.refresh_token` → sealed file `refresh_token.enc`, `<user_id>.two_factor_remember` → key-less file `two_factor_remember.enc`; any other name is refused. `user_id` is checked with the same rule as layout.rs account ids (no separators, ≤ 64 chars).
  - `delete` and `delete_all_for` never need a key: logout calls `delete_all_for` after the session already zeroized the user key.
done-when: `cargo test -p vk-vault sealed_store`; `cargo clippy -p vk-vault --all-targets -- -D warnings`; tests cover round trip, wrong key, tampered header, locked get, delete and delete_all_for without a key, key-less wrapper-only names, refused names
dont: change the macOS keychain path
needs: 0a
difficulty: medium
kind: change

## 1m Vault provides and forgets the token key
files: crates/vault/src/
do: - The vault session calls `provide_key` right after the user key becomes available (password login, unlock, biometric unlock) and `forget_key` when it is zeroized (lock, log out, account switch), through a hook on `SecretStore` with default no-op methods so the keychain store and `MemorySecretStore` are unchanged.
  - Order: in `complete_login` (crates/vault/src/session.rs) `provide_key` runs before `store_login_secrets`; the 2FA-remember token is read before login and uses the key-less name.
  - `sync::refresh` (crates/vault/src/vault/sync.rs) maps `Undecryptable` to deleting that file and the existing `Unauthorized` path (log in again), exactly like a token the server rejects. `Locked` cannot happen there because refresh runs only while unlocked: log it at error level and treat it as `Unauthorized` too.
done-when: `cargo test -p vk-vault`; `cargo clippy -p vk-vault --all-targets -- -D warnings`; tests with SealedFileStore cover login → lock → unlock → sync with the refresh token, login → logout (key already forgotten) → files gone, account switch, and an undecryptable token → logged out
needs: 1l
difficulty: medium
kind: change

## 2a Named-pipe listener
files: crates/ipc/src/transport/windows.rs, crates/ipc/Cargo.toml
do: - `Listener::bind` for a pipe name, with tokio `ServerOptions`: `first_pipe_instance(true)`, `reject_remote_clients(true)`, security attributes from `vk_win::sddl::pipe(sid)`. `ERROR_ACCESS_DENIED` on the first instance means the name is squatted: fail with an error naming the pipe; never fall back to another name.
  - The DACL denies FILE_CREATE_PIPE_INSTANCE to everyone including us (§5.3), so create a pool of instances while creating the first one, and recycle each instance after its client disconnects (`disconnect` then `connect` again) instead of creating new ones. Pool size: 4 for CLI and browser.
  - Verify the "no new instance" assumption at runtime: if creating the pool's extra instances fails with access denied, create them with a DACL that allows FILE_CREATE_PIPE_INSTANCE and then tighten every instance handle with SetSecurityInfo (open them with WRITE_DAC; do not assume one instance's descriptor covers the others). Record which path ran in a debug log.
  - A connection that sends nothing for 30 s is dropped, so a few idle clients cannot hold the whole pool forever.
done-when: `scripts/check-windows.sh -p vk-ipc --all-targets`; `cargo test -p vk-ipc`
needs: 1g
difficulty: hard
kind: change

## 2b Named-pipe client with server check
files: crates/ipc/src/transport/windows.rs
do: `connect(&Endpoint)` opens the pipe (retry on ERROR_PIPE_BUSY with WaitNamedPipeW up to 2 s), then checks the server: GetNamedPipeServerProcessId → `vk_win::ImageIdentity::of_pid` must equal `of_current_exe()`, and the server's session must be ours. A mismatch is a hard error: "another program is serving Vaultkeeper's pipe", or, when the server's image path equals ours but the file id differs, "Vaultkeeper was updated; restart it". In vw-it builds keep the existing any-peer escape hatch.
done-when: `scripts/check-windows.sh -p vk-ipc --all-targets`
needs: 2a
difficulty: medium
kind: change

## 2c Client check on accept and Windows integration tests
files: crates/ipc/src/transport/windows.rs, crates/ipc/src/peer.rs, crates/ipc/tests/windows_pipes.rs
do: - On accept: GetNamedPipeClientProcessId and GetNamedPipeClientSessionId into `PeerCredentials { pid, session_id }`; `SameExecutable::verify` on Windows compares `ImageIdentity::of_pid(pid)` with its own and the session with ours. Status: a mistake guard, as on Linux (§5.3).
  - `#[cfg(windows)]` integration tests (run in CI): round trip through bind/connect; second `bind` of the same name fails; after bind, a plain `ServerOptions::new().create(name)` without the first-instance flag from the same process fails with access denied (proves the DACL, not only the flag); five sequential clients on a pool of four all succeed (recycling works); a client from the test exe passes `SameExecutable::current()`; a foreign identity is rejected.
  - Add `-p vk-ipc` to `WINDOWS_PACKAGES` in .github/workflows/ci.yml.
done-when: `scripts/check-windows.sh -p vk-ipc --all-targets`; `cargo test -p vk-ipc`
needs: 2b
difficulty: medium
kind: change

## 2d Hardened child spawn on Windows
files: crates/win/src/spawn.rs, crates/win/src/lib.rs
do: - `spawn_hardened(exe, args, SpawnOptions) -> io::Result<Child>` with raw CreateProcessW + STARTUPINFOEXW, because std's `spawn_with_attributes` is still unstable on 1.99. Options: process security descriptor (`sddl::process(sid)`) and thread security descriptor (`sddl::thread(sid)`), `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` with handles to inherit and only those (the list replaces default inheritance, so std handles are passed explicitly when wanted; with no handles, bInheritHandles is FALSE), `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` flags, creation flags (CREATE_UNICODE_ENVIRONMENT, plus DETACHED_PROCESS / CREATE_NEW_PROCESS_GROUP / CREATE_BREAKAWAY_FROM_JOB for detached starts).
  - Quote arguments with the MSVC rules; portable quoting function with unit tests on macOS.
  - `Child` owns the process handle (full access from creation, so the launcher can still TerminateProcess a hung UI after its DACL is locked down) and offers `pid()`, `kill()` and `async wait()` (WaitForSingleObject on a blocking task, or RegisterWaitForSingleObject).
done-when: `cargo test -p vk-win`; `scripts/check-windows.sh -p vk-win --all-targets`
needs: 1a
difficulty: hard
kind: change

## 2e Inherited UI channel
files: crates/ipc/src/transport/windows.rs, crates/ipc/src/transport.rs, app/src/daemon/launcher.rs, app/src/ui_process/mod.rs, app/src/run.rs
do: - Daemon side (§5.2): create a pipe named `\\.\pipe\vaultkeeper.ui.<128-bit hex from the OS CSPRNG>` with one instance and the pipe DACL, open its client end inheritable with FILE_FLAG_OVERLAPPED (tokio requires overlapped handles), then check GetNamedPipeClientProcessId on the server end equals our own pid before anything else; any other pid → close both and retry with a new name.
  - The launcher spawns `--ui --ui-pipe <handle value>` through `vk_win::spawn_hardened` with that handle in the handle list, the process DACL and the UI mitigation set (2i), closes its copy of the client handle after spawn, and serves the server end as the UI connection with no peer check. macOS keeps tokio Command and ui.sock.
  - The UI checks the handle before it sends anything (a same-user program could start `--ui --ui-pipe <its own pipe>` to collect the master password): GetNamedPipeServerProcessId(handle) must equal the UI's parent pid, and `ImageIdentity::of_pid(parent)` must equal `of_current_exe()`; otherwise exit with an error. Then it wraps the handle (`NamedPipeClient::from_raw_handle`) into `RemoteVault::from_stream` and keeps the server pid as `daemon_pid` (used by 4d). Reject `--ui-pipe` on non-Windows.
  - Launcher reaping and the hung-UI kill use `vk_win::Child` on Windows.
done-when: `scripts/check-windows.sh -p vk-ipc -p vaultkeeper --all-targets`; `cargo test -p vaultkeeper launcher`
needs: 2c, 2d, 1o
difficulty: hard
kind: change

## 2f Private data directory ACL
files: crates/platform/src/fs.rs, crates/platform/src/fs/, crates/platform/Cargo.toml
do: `ensure_private_dir` on Windows creates the directory, applies `sddl::private_dir(sid)` with SetNamedSecurityInfoW (DACL protected + mandatory label), and sets FILE_ATTRIBUTE_NOT_CONTENT_INDEXED (§4.3). Files inside inherit; `write_private_atomic` needs no per-file ACL on Windows.
done-when: `scripts/check-windows.sh -p vk-platform --all-targets`; `cargo test -p vk-platform fs`
needs: 1a
difficulty: medium
kind: change

## 2g DPAPI blob wrapper
files: crates/platform/src/dpapi.rs, crates/platform/src/lib.rs
do: `dpapi::{protect(data, entropy), unprotect(blob, entropy)}` with CryptProtectData/CryptUnprotectData in user scope, CRYPTPROTECT_UI_FORBIDDEN; callers pass entropy = constant ‖ user id (§4.1). Output buffers freed with LocalFree; plaintext returned as Zeroizing. vk-platform must not depend on vk-vault: the app adapts these functions to `BlobWrapper` in 2p. Windows-only module; `#[cfg(windows)]` round-trip and wrong-entropy tests.
done-when: `scripts/check-windows.sh -p vk-platform --all-targets`
needs: 1a
difficulty: easy
kind: change

## 2h Startup checks: refuse or repair
files: crates/platform/src/fs/, crates/platform/src/fs.rs
do: `verify_private_dir(path) -> Result<Repair, Refusal>` on Windows (§4.4): open with FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS; refuse a reparse point, an owner other than the user or Administrators, or an ACE for any SID other than user, SYSTEM, Administrators; otherwise rewrite DACL, label and attribute when they differ. Same check for a list of files. The Unix counterpart (owner, mode 0700/0600, symlink) is left for the Linux work; on Unix the function is an explicit no-op returning `Ok(Repair::None)`, so macOS behaviour is unchanged.
done-when: `scripts/check-windows.sh -p vk-platform --all-targets`; `cargo test -p vk-platform fs`
needs: 2f
difficulty: hard
kind: change

## 2i Process hardening
files: crates/platform/src/hardening.rs, crates/platform/src/hardening/
do: - `harden_process(Role)`, where `Role` is Daemon or Ui (macOS ignores it). On Windows, first thing: SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32), the process DACL from `sddl::process(sid)` via SetSecurityInfo, then SetProcessMitigationPolicy for ExtensionPointDisable, image load (NoRemoteImages, NoLowMandatoryLabelImages, PreferSystem32Images), ProhibitDynamicCode and StrictHandleCheck.
  - `MicrosoftSignedOnly` (daemon only) and `ExtensionPointDisable` in the UI are off unless `VAULTKEEPER_STRICT_MITIGATIONS=1`, until the user's antivirus, IME and screen-reader tests (checklist 7a) pass. Export the UI flag set as a constant for `spawn_hardened` (2e).
  - Each failing policy is logged and does not abort.
done-when: `scripts/check-windows.sh -p vk-platform --all-targets`; `cargo test -p vk-platform hardening`; `cargo check -p vaultkeeper`
needs: 1a
difficulty: medium
kind: change

## 2j Atomic writes and volume checks on Windows
files: crates/platform/src/fs.rs, crates/platform/src/fs/
do: `write_private_atomic` retries the rename on ERROR_SHARING_VIOLATION and ERROR_ACCESS_DENIED up to 5 times with 20/40/80/160/320 ms backoff (antivirus scans the temp file, §4.5); std's rename on Windows already uses FileRenameInfoEx with POSIX semantics. Windows versions of `is_writable_dir` and `is_on_read_only_volume` (GetVolumeInformationByHandleW, FILE_READ_ONLY_VOLUME). `swap` stays macOS-only (the Windows updater runs the installer, step 5h).
done-when: `scripts/check-windows.sh -p vk-platform --all-targets`; `cargo test -p vk-platform fs`
needs: 2f
difficulty: medium
kind: change

## 2k Single instance on Windows
files: crates/platform/src/single_instance.rs, crates/platform/src/single_instance/
do: - `acquire_in` on Windows: named mutex `Global\Vaultkeeper-<sid>` with the `sddl::mutex` DACL decides who is first, so one user has one daemon even with a console and an RDP session open at once (the data directory and the machine-wide pipe names are per user). ERROR_ALREADY_EXISTS → second instance; access denied → refuse with a clear message (someone pre-created our name). If creating a Global\ mutex fails for lack of privilege, fall back to `Local\` and log it.
  - The first instance serves `Command`s on the `….instance` pipe with the vk-win pipe DACL and first-instance flag, using synchronous CreateNamedPipeW/ConnectNamedPipe on a dedicated thread (vk-platform has no tokio and must not depend on vk-ipc). The second instance checks the server's image identity (as in 2b) before it sends its command, then exits.
  - Add `Command::Quit` (also on Unix) and a `--quit` flag in the app that sends it, so the installer, uninstaller and updater can stop a running daemon.
  - `wait_for_exit(pid, timeout)` via OpenProcess(SYNCHRONIZE) + WaitForSingleObject. Keep the Command encoding shared with Unix.
done-when: `scripts/check-windows.sh -p vk-platform --all-targets`; `cargo test -p vk-platform single_instance`; `cargo check -p vaultkeeper`
needs: 1h, 1a, 1o
difficulty: medium
kind: change

## 2l Screen lock, sleep and session end events
files: crates/platform/src/power.rs, crates/platform/src/power/
do: On Windows a dedicated thread owns a message-only window (HWND_MESSAGE, never shown, so the daemon stays windowless from Slint's view) and reports the same events power.rs exposes on macOS: WTSRegisterSessionNotification → WTS_SESSION_LOCK as screen lock; PowerRegisterSuspendResumeNotification → suspend as sleep; WM_QUERYENDSESSION/WM_ENDSESSION → a new `SessionEnding` event the daemon handles by locking and flushing (§7.3). Unregister on drop.
done-when: `scripts/check-windows.sh -p vk-platform --all-targets`; `cargo test -p vk-platform power`; `cargo check -p vaultkeeper`
needs: 0b
difficulty: medium
kind: change

## 2m Network change events
files: crates/platform/src/network.rs, crates/platform/src/network/
do: Windows backend with NotifyNetworkConnectivityHintChange delivering the same "network changed" signal the macOS watcher sends (the daemon then runs its existing `/alive` probe). Cancel with CancelMibChangeNotify2 on drop.
done-when: `scripts/check-windows.sh -p vk-platform --all-targets`; `cargo test -p vk-platform network`
needs: 0b
difficulty: easy
kind: change

## 2n Clipboard exclusions
files: crates/platform/src/clipboard.rs
do: On Windows, secrets are set through arboard's Windows extension with exclusion from clipboard history, cloud clipboard and monitor processing (`ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory`=0, `CanUploadToCloudClipboard`=0, §7.4). The SHA-256 auto-clear rule is unchanged.
done-when: `scripts/check-windows.sh -p vk-platform --all-targets`; `cargo test -p vk-platform clipboard`
needs: 0b
difficulty: easy
kind: change

## 2o Autostart on Windows
files: crates/platform/src/autostart.rs, crates/platform/tests/autostart.rs
do: Windows uses auto-launch's Run key with `"<exe>" --tray`, `is_enabled` also reads `Explorer\StartupApproved\Run` so a user's "off" in Settings → Apps → Startup is reported (§1, §7.6); `started_by_login_agent` checks for the `--tray` argument; `refresh` rewrites the command if the exe moved. LaunchAgent code becomes `cfg(target_os = "macos")`.
done-when: `scripts/check-windows.sh -p vk-platform --all-targets`; `cargo test -p vk-platform autostart`
needs: 0b
difficulty: medium
kind: change

## 2p Windows token store wired into the daemon
files: app/src/daemon/secrets.rs, app/src/daemon/mod.rs
do: On Windows the daemon builds `SealedFileStore` with a `BlobWrapper` adapter over `vk_platform::dpapi` (entropy constant ‖ user id): refresh token sealed + DPAPI, 2FA-remember token DPAPI only (§4.1), written with `vk_platform::fs::write_private_atomic` under the account directory. macOS keeps `KeychainStore`. Add `-p vk-platform` Windows tests that already exist to CI if not listed.
done-when: `scripts/check-windows.sh -p vaultkeeper --all-targets`; `cargo test -p vaultkeeper secrets`
needs: 1m, 2g, 1o
difficulty: medium
kind: change

## 3a Windows manifest, icon and resources
files: app/build.rs, app/Cargo.toml, packaging/windows/, scripts/make-windows-icon.sh
do: - packaging/windows/vaultkeeper.manifest: PerMonitorV2 DPI awareness, Common Controls v6, UTF-8 active code page, Windows 10/11 supportedOS GUID, `<consoleAllocationPolicy>detached</consoleAllocationPolicy>` (§7.11, §7.12), asInvoker.
  - scripts/make-windows-icon.sh builds packaging/windows/vaultkeeper.ico (16–256 px) from the existing app icon SVG with rsvg-convert and ImageMagick; commit the generated .ico.
  - app/build.rs embeds manifest, icon and VERSIONINFO (from the workspace version) only when `CARGO_CFG_TARGET_OS == "windows"`, through `embed-resource`. The binary stays console-subsystem (no `windows_subsystem` attribute).
done-when: `scripts/check-windows.sh -p vaultkeeper --all-targets`; `cargo build -p vaultkeeper`
deps: embed-resource@3
needs: 1o
difficulty: medium
kind: change

## 3b Detached daemon start and console handling
files: app/src/run.rs, app/src/main.rs, app/src/browser_host/mod.rs
do: - Windows: when `vaultkeeper` or `--tray` must become the daemon and the process has a console (GetConsoleWindow() != 0) or was started by the browser host, and the hidden `--detached` marker is absent, re-launch the same exe with `--detached` added through `vk_win::spawn_hardened` with DETACHED_PROCESS, CREATE_NEW_PROCESS_GROUP and CREATE_BREAKAWAY_FROM_JOB (falling back without breakaway if the job forbids it), then return (§7.11). A process with `--detached` never re-launches, so there is no loop. The browser host's macOS `open -g -a` path stays.
  - The daemon calls `harden_process(Role::Daemon)`, the UI `harden_process(Role::Ui)`.
  - SIGTERM handling becomes `cfg(unix)`; on Windows a console control handler (CTRL_CLOSE/LOGOFF/SHUTDOWN) and the `SessionEnding` event (2l) trigger the same graceful quit.
done-when: `scripts/check-windows.sh -p vaultkeeper --all-targets`; `cargo test -p vaultkeeper run`
needs: 2d, 2i, 2l, 3a
difficulty: hard
kind: change

## 3c Tray icon style setting (portable)
files: app/src/settings.rs, app/ui/, app/src/daemon/tray.rs, app/assets/
do: Extend today's "Menu bar icon: Auto / White / Black" choice with `Blue`; default Blue on Windows and Auto on macOS (existing macOS settings files keep their value). Add the blue glyph asset: the tray shield in flat `#2F6BEA` with the keyhole filled white (§7.1). Label the setting "Tray icon" on Windows. Settings serde stays backward compatible.
done-when: `cargo test -p vaultkeeper settings`; `cargo test -p vaultkeeper tray`; `cargo clippy -p vaultkeeper --all-targets -- -D warnings`
needs: 1o
difficulty: medium
kind: change

## 3d Taskbar theme and DPI for the tray icon
files: app/src/daemon/tray.rs, app/src/os/
do: Windows `Auto` picks White/Black from `HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\SystemUsesLightTheme` (not AppsUseLightTheme), watched with RegNotifyChangeKeyValue on a thread (no window, §7.1); High Contrast follows the contrast theme. Rasterise the tray SVG at GetSystemMetricsForDpi(SM_CXSMICON) and hand Slint `Image::from_rgba8`, re-rasterising on DPI change.
done-when: `scripts/check-windows.sh -p vaultkeeper --all-targets`
needs: 3c
difficulty: medium
kind: change

## 3e Hotkey default and foreground hand-off
files: app/src/daemon/hotkey.rs, app/src/settings.rs, app/src/daemon/launcher.rs, app/src/os/
do: Default Quick Panel hotkey on Windows is Ctrl+Shift+Space (⌘⇧Space stays on macOS; no Win+ or Ctrl+Alt chords, §7.2). Before the daemon tells the UI to show any window it calls AllowSetForegroundWindow(ui_pid); the UI calls SetForegroundWindow on show. The pid comes from the launcher's `Child`.
done-when: `scripts/check-windows.sh -p vaultkeeper --all-targets`; `cargo test -p vaultkeeper hotkey`
needs: 2e
difficulty: medium
kind: change

## 3f Quick Panel placement and window glue
files: app/src/os/appkit.rs, app/src/os/windows_shell.rs, app/src/os/mod.rs
do: Windows implementations of the `placement` hook (GetCursorPos + MonitorFromPoint + GetMonitorInfoW work area, DPI-scaled) and the `dock` hook (no-op: the taskbar button follows the Manager window). Move the AppKit implementations under `cfg(target_os = "macos")` unchanged.
done-when: `scripts/check-windows.sh -p vaultkeeper --all-targets`; `cargo clippy -p vaultkeeper --all-targets -- -D warnings`
needs: 1o
difficulty: medium
kind: change

## 3g Capture exclusion setting
files: app/src/settings.rs, app/ui/, app/src/os/windows_shell.rs, app/src/app/
do: Setting "Hide Vaultkeeper from screenshots and screen sharing" (Windows only, default on). When on, every Vaultkeeper window gets SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE) on show, which also keeps them out of Recall (§7.12). The HWND comes from Slint's winit window (`unstable-winit-030`, raw-window-handle Win32).
done-when: `scripts/check-windows.sh -p vaultkeeper --all-targets`; `cargo test -p vaultkeeper settings`
needs: 3f
difficulty: medium
kind: change

## 3h Vendored SSH agent pipe patch
files: vendor/ssh_agent/src/server/listener/windows.rs, vendor/ssh_agent/src/server/peer_info.rs, vendor/ssh_agent/Cargo.toml, vendor/PATCHES.md
do: - The Windows listener creates its first instance with FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_REJECT_REMOTE_CLIENTS and the explicit DACL `D:P(A;;0x12019b;;;<sid>)(A;;RC;;;OW)` (via `windows` 0.62 calls already in that crate), with the same pool-and-recycle approach as step 2a. Creation failing because the name exists returns an error the app shows as "The Windows OpenSSH Authentication Agent service is running; stop and disable it, or turn off Vaultkeeper's SSH agent" (§7.10).
  - peer_info.rs: Windows process name from the client pid through sysinfo.
  - Update the vendored Windows tests that create the pipe name twice so they match the first-instance behaviour.
  - Record the patch in vendor/PATCHES.md in the existing style. Keep the diff minimal.
done-when: `scripts/check-windows.sh -p ssh_agent --all-targets`; `cargo test -p ssh_agent`
needs: 1i
difficulty: medium
kind: change

## 3i SSH settings text on Windows
files: app/ui/, app/src/settings.rs, app/src/os/misc.rs, docs/USAGE.md
do: On Windows the SSH settings show the pipe `\\.\pipe\openssh-ssh-agent` instead of `SSH_AUTH_SOCK`, plus the hint that Git for Windows needs `core.sshCommand = C:/Windows/System32/OpenSSH/ssh.exe` and WSL needs a relay such as npiperelay. Add a Windows section to docs/USAGE.md with the same facts.
done-when: `cargo test -p vaultkeeper settings`; `scripts/check-windows.sh -p vaultkeeper --all-targets`
needs: 3h
difficulty: easy
kind: change

## 3j CLI on Windows
files: app/src/cli.rs, app/src/cli_access.rs, app/src/exec.rs
do: The CLI connects to the `….cli` pipe through `transport` (server check from 2b) and prints to the parent console; if output does not appear under the detached console policy, call AttachConsole(ATTACH_PARENT_PROCESS) first (§7.11, open point for checklist 7a). Piped output works through inherited handles. Commands that start the daemon use the detached start from 3b.
done-when: `scripts/check-windows.sh -p vaultkeeper --all-targets`; `cargo test -p vaultkeeper cli`
needs: 3b
difficulty: medium
kind: change

## 3k Startup checks wired into daemon and UI
files: app/src/daemon/mod.rs, app/src/ui_process/mod.rs, app/src/run.rs
do: Both processes run `verify_private_dir` (2h) on the data directory and the account files (`account.json`, token files, `hello.bin`) at start. Repairs are logged; a refusal shows a clear error (daemon: tray notification and exit; UI: error dialog) and never continues with a suspicious directory. macOS behaviour unchanged.
done-when: `scripts/check-windows.sh -p vaultkeeper --all-targets`; `cargo test -p vaultkeeper`
needs: 2h, 3b
difficulty: medium
kind: change

## 3l Windows CI covers the whole workspace
files: .github/workflows/ci.yml
do: Replace `WINDOWS_PACKAGES` with `--workspace` for clippy and tests on windows-latest. Tests that need a desktop session (tray, hotkey, Slint testing backend) stay enabled if they pass headless on the runner, otherwise get `#[cfg_attr(windows, ignore = "needs an interactive session")]` with that reason.
done-when: `ruby -ryaml -e 'YAML.load_file(".github/workflows/ci.yml")'`; `scripts/check-windows.sh --workspace --all-targets`
needs: 3k, 3j, 3i, 3g, 3e, 3d, 2p, 2k, 2m, 2n, 2o
difficulty: easy
kind: change

## 4a Windows Hello spike (hardware gate)
files: crates/platform/examples/hello_check.rs, crates/platform/Cargo.toml
do: A console example the user runs on their PC (§3.2, §10 risks 1–2, 9): open or create the Passport KSP key `<SID>//Vaultkeeper//Vaultkeeper` (print the exact name that worked), export BCRYPT_RSAPUBLIC_BLOB, RSA-OAEP-SHA256-encrypt 32 random bytes (fall back to PKCS#1 v1.5 and report which worked), then NCryptDecrypt with NCRYPT_WINDOW_HANDLE_PROPERTY = the console's window, NCRYPT_USE_CONTEXT_PROPERTY text, NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY = 1, retrying once on 0x80098044. Print every HRESULT/NTSTATUS. Flags: `--strict` applies `harden_process(Role::Daemon)` first; `--delete` removes the key.
done-when: `scripts/check-windows.sh -p vk-platform --examples`
needs: 2i, 7a
difficulty: medium
kind: change
gate: lifted by the user (no Windows PC available): 4c–4f are built from the research and this spike's code; the user runs `hello_check` and `hello_check --strict` later and 4c is corrected from its output

## 4b Envelope v2 with primitive ids (portable)
files: crates/platform/src/biometric/envelope.rs
do: Version 2 envelope: `magic ‖ version ‖ primitive_id ‖ key name ‖ public key blob ‖ user SID ‖ wrapped KEK ‖ nonce ‖ ciphertext+tag`, length-prefixed, the whole header as AES-GCM associated data (§3.2). Primitive ids: 1 = Secure Enclave P-256 ECDH, 2 = Passport RSA-OAEP KEK, 3 and 4 reserved and rejected. Version 1 files (macOS today) still open unchanged; new macOS enrolments keep writing v1 so macOS behaviour does not change. Unknown or reserved ids → "enrol again".
done-when: `cargo test -p vk-platform envelope`; `cargo clippy -p vk-platform --all-targets -- -D warnings`; tests cover v1 compatibility, v2 round trip, header tampering, reserved ids
needs: 0b
difficulty: medium
kind: change

## 4c Passport KSP backend
files: crates/platform/src/biometric.rs, crates/platform/src/biometric/passport.rs
do: Windows biometric backend implementing the same enrol/unlock surface as Secure Enclave: enrol without a prompt (export public key, OAEP-wrap a fresh 32-byte KEK, AES-256-GCM the user key, v2 envelope id 2); unlock with one NCryptDecrypt using the parameters proven by the 4a spike. Error mapping keeps the biometric.rs invariant (§3.2): `BiometricInvalidated` only for NTE_BAD_KEYSET/NTE_NO_KEY from NCryptOpenKey after NCryptOpenStorageProvider succeeded (a provider that fails to open, e.g. NGC service down or RDP, is `BiometricFailed`), a stored public key that differs from the KSP's, or a GCM failure after a successful unwrap; everything else, including cancel, lockout, TPM busy, 0x80098044 after its retry and unknown codes, is `BiometricFailed`. Availability probe: the KSP opens and the session is not remote (GetSystemMetrics(SM_REMOTESESSION)).
done-when: `scripts/check-windows.sh -p vk-platform --all-targets`; `cargo test -p vk-platform biometric`
unverified: no hardware run yet; mirror the NCrypt calls in crates/platform/examples/hello_check.rs exactly
needs: 4a, 4b
difficulty: hard
kind: change

## 4d Hello prompt parented to the UI window
files: crates/ipc/src/protocol.rs, crates/ipc/src/touch_id.rs, crates/ipc/src/server/dispatch.rs, app/src/os/biometrics.rs, app/src/daemon/
do: The unlock and enrol requests carry an optional `parent_window: u64` (§3.3). The daemon accepts it only if IsWindow(hwnd) and GetWindowThreadProcessId(hwnd) equals the pid of the UI child it spawned; otherwise it ignores the handle. The UI calls AllowSetForegroundWindow(daemon_pid) before sending (daemon_pid from GetNamedPipeServerProcessId on the inherited handle, kept by 2e), and suspends the Quick Panel's hide-on-deactivate until the daemon answers. macOS ignores the field. Protocol stays backward compatible within one build (both ends ship together).
done-when: `cargo test -p vk-ipc`; `scripts/check-windows.sh -p vk-ipc -p vaultkeeper --all-targets`
needs: 4c, 3e
difficulty: medium
kind: change

## 4e Biometric labels and availability in the UI
files: app/ui/, app/src/
do: One `biometric-label` property ("Touch ID" / "Windows Hello"); rename `touch-id-*` properties to `biometric-*` in .slint and Rust; hide the enrol row when Hello is unavailable (probe from 4c, rechecked when the settings open); keep "Require master password on app start" visible on Windows (§3.5). The passkey user-verification fallback in app/src/daemon/browser/dispatch.rs uses the same backend.
done-when: `cargo test -p vaultkeeper`; `cargo clippy -p vaultkeeper --all-targets -- -D warnings`; `scripts/check-windows.sh -p vaultkeeper --all-targets`
needs: 4d
difficulty: medium
kind: change

## 4f "SSH requires Windows Hello"
files: crates/platform/src/biometric/, app/src/daemon/ssh.rs, crates/platform/Cargo.toml
do: The daemon's SSH approval check on Windows uses IUserConsentVerifierInterop::RequestVerificationForWindowAsync(ui_hwnd, message) from `windows` 0.62 on a worker thread initialised with RoInitialize(RO_INIT_MULTITHREADED) (§3.3). Only `Verified` passes; every other result denies. The window handle is validated as in 4d.
done-when: `scripts/check-windows.sh -p vk-platform -p vaultkeeper --all-targets`
needs: 4d
difficulty: medium
kind: change

## 5a Auto-type with SendInput
files: app/src/os/autotype.rs, app/src/os/autotype/
do: Windows backend (§7.5): remember GetForegroundWindow() before the Quick Panel opens and restore it before typing; wait until the hotkey's modifiers are released; send KEYEVENTF_UNICODE down/up pairs (surrogate pairs for non-BMP) in batches and check SendInput's inserted count; a short count or 0 means UIPI (elevated target) → the existing "could not type" error with that reason. No permission prompt exists on Windows, so `is_trusted` is true.
done-when: `scripts/check-windows.sh -p vaultkeeper --all-targets`; `cargo test -p vaultkeeper autotype`
needs: 3e
difficulty: medium
kind: change

## 5b webauthn.dll assertion FFI
files: app/src/os/security_key/, app/src/os/security_key.rs
do: Windows security-key backend over `webauthn.dll` (windows-sys `Win32_Networking_WindowsWebServices`: WebAuthNGetApiVersionNumber, WebAuthNAuthenticatorGetAssertion, WebAuthNFreeAssertion) taking the server's challenge, RP id, allowed credential ids and the AppID extension, parented to the login window's HWND. Return the same assertion type the `authenticator` path returns. Windows draws its own PIN and touch UI.
done-when: `scripts/check-windows.sh -p vaultkeeper --all-targets`
needs: 1o
difficulty: hard
kind: change

## 5c Security-key login on Windows
files: app/src/os/security_key.rs, app/src/app/, app/ui/
do: Wire 5b into the two-step login: on Windows the login window shows only "Follow the Windows prompt" while the call runs, and cancel maps to the existing cancelled outcome.
done-when: `scripts/check-windows.sh -p vaultkeeper --all-targets`; `cargo test -p vaultkeeper security_key`
needs: 5b
difficulty: medium
kind: change

## 5d Native messaging registration
files: app/src/os/browser.rs, app/src/os/browser/
do: Portable manifest JSON generation (tested on macOS) and, on Windows, per-user registration: write manifests under the data dir and set the default value of `HKCU\Software\{Google\Chrome,Microsoft\Edge,BraveSoftware\Brave-Browser,Chromium}\NativeMessagingHosts\<name>` and `HKCU\Software\Mozilla\NativeMessagingHosts\<name>` to the manifest path (§7.8). Unregister removes them.
done-when: `cargo test -p vaultkeeper browser`; `scripts/check-windows.sh -p vaultkeeper --all-targets`
needs: 1o
difficulty: medium
kind: change

## 5i Authenticode signer check in vk-win
files: crates/win/src/authenticode.rs, crates/win/src/lib.rs
do: `signer_subject(path) -> io::Result<Option<String>>`: WinVerifyTrust with WINTRUST_ACTION_GENERIC_VERIFY_V2 and no UI (revocation check off, so offline machines work), and only when it succeeds the signer's subject CN from CryptQueryObject + CryptMsgGetParam + CertGetNameStringW. Unsigned or invalid → `Ok(None)`. Also `is_validly_signed(path) -> bool` for the updater (5h).
done-when: `scripts/check-windows.sh -p vk-win --all-targets`; a #[cfg(windows)] test checks that C:\Windows\explorer.exe reports "Microsoft Windows" or "Microsoft Corporation"
needs: 1a
difficulty: medium
kind: change

## 5e Browser host parent identification
files: app/src/browser_host/parent.rs, app/src/browser_host/parent/
do: Windows: find the parent with a Toolhelp32 snapshot; if it is `cmd.exe` (Chromium without NativeHostsExecutablesLaunchDirectly), use cmd's parent. Reject a parent whose creation time (GetProcessTimes) is later than its child's, which catches a reused pid. Identify the browser with `vk_win::authenticode::signer_subject` against an allowlist: Google LLC, Microsoft Corporation, Mozilla Corporation, Brave Software, Inc. Return the same ParentInfo as macOS; an unknown or unsigned parent keeps today's "unknown browser" handling. Keep the parent-chain choice (skip one cmd.exe, creation-time rule) a portable function over plain process records with unit tests on macOS.
done-when: `scripts/check-windows.sh -p vaultkeeper --all-targets`; `cargo test -p vaultkeeper parent`
needs: 1o, 5i
difficulty: medium
kind: change

## 5f Browser socket on Windows
files: app/src/daemon/browser/control.rs, app/src/browser_host/mod.rs, app/tests/browser_daemon/
do: The daemon serves the `….browser` pipe and the host connects to it through `transport` (with the server check). The browser daemon test harness gets a Windows variant or is cfg'd to Unix with a reason.
done-when: `scripts/check-windows.sh -p vaultkeeper --all-targets`; `cargo test -p vaultkeeper --test browser_daemon`
needs: 5e, 5d
difficulty: medium
kind: change

## 5g Update signature verification (portable)
files: app/src/daemon/update/, app/Cargo.toml
do: - Ed25519 (minisign-format) detached signature check of downloaded assets against a public key embedded in the binary (§8.3). The signed trusted comment is `vaultkeeper <version> <asset name>`; the check requires a valid signature over both file and comment, the comment's version equal to the release tag's version and greater than `Version::current()`, and the asset name equal to the file being installed. That refuses a downgrade or a swapped asset published by anyone holding only the GitHub token.
  - Asset selection by OS/arch: `Vaultkeeper-<tag>-x64-setup.exe` on Windows, the existing arm64 names on macOS.
  - Downloads go to `data_dir/updates/<random>/` (private ACL from 2f), never %TEMP%; the verified file is executed from that same path and the directory is removed afterwards.
  - The public key constant is a placeholder that fails closed (updates refused, logged) until the user generates the key. Key rotation is out of scope for this step. macOS keeps its current code-signature check as well.
done-when: `cargo test -p vaultkeeper update`; `cargo clippy -p vaultkeeper --all-targets -- -D warnings`; portable tests cover a good signature, a tampered file, a downgrade (older version in the comment), an asset-name mismatch and the placeholder key refusing everything
deps: ed25519-dalek@2
needs: 1o
difficulty: medium
kind: change

## 5h Windows updater installs through the installer
files: app/src/daemon/update/
do: - On Windows the updater downloads the setup exe as in 5g, verifies the Ed25519 signature and a valid Authenticode chain (`vk_win::authenticode::is_validly_signed`, publisher not pinned). Both are required: an unsigned build never self-updates (users of unsigned builds update by hand), so nothing depends on an "unsigned" mark.
  - Before running the installer the daemon stops what holds the exe: it kills and waits for its UI child (`vk_win::Child`), closes the SSH, CLI and browser pipes, then spawns the installer detached with `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART` and exits. Restart Manager does not see a windowless daemon, so it cannot be relied on.
  - Running the installer instead of swapping the exe keeps the Add/Remove Programs version, and so winget, correct.
done-when: `scripts/check-windows.sh -p vaultkeeper --all-targets`; `cargo test -p vaultkeeper update`
needs: 5g, 5i, 3b, 2k
difficulty: medium
kind: change

## 6a Inno Setup per-user installer
files: packaging/windows/vaultkeeper.iss, scripts/bundle-windows.ps1
do: - vaultkeeper.iss: fixed AppId GUID, `PrivilegesRequired=lowest`, `DefaultDirName={localappdata}\Programs\Vaultkeeper`, x64 only (`ArchitecturesAllowed=x64os`, `ArchitecturesInstallIn64BitMode=x64os`), `MinVersion=10.0.26100`, version from a define, Start menu shortcut, add/remove the install dir in `HKCU\Environment` Path (broadcast WM_SETTINGCHANGE), `CloseApplications=yes`, start `vaultkeeper.exe --tray` after install. Install, upgrade and uninstall first run `vaultkeeper.exe --quit` (step 2k) and wait for the daemon to exit; uninstall then removes the Run value and the NativeMessagingHosts keys it owns; user data in %LOCALAPPDATA%\Vaultkeeper stays unless the user ticks a checkbox.
  - scripts/bundle-windows.ps1: `cargo build --release --locked --target x86_64-pc-windows-msvc -p vaultkeeper`, then `iscc` with the version from scripts/version.sh logic, output `out/Vaultkeeper-<tag>-x64-setup.exe` and a portable `out/Vaultkeeper-<tag>-x64.zip`.
done-when: files exist; `grep -q PrivilegesRequired=lowest packaging/windows/vaultkeeper.iss`
needs: 3a
difficulty: medium
kind: change

## 6b Release jobs for Windows: build without secrets, sign separately
files: .github/workflows/release.yml, scripts/bundle-windows.ps1
do: - Job `windows-build` (windows-latest, no `environment`, no secrets): toolchain, rust-cache with shared key `windows-release` and `save-if: false`, `AWS_LC_SYS_PREBUILT_NASM=1`, `cargo build --release --locked`, uploads the unsigned `vaultkeeper.exe`. Build scripts of dependencies run here, where no signing key exists.
  - Job `windows-package` (windows-latest, environment `release`, needs `windows-build`, runs no cargo and no package manager): downloads the exe; if `WINDOWS_SIGN_PFX`/`WINDOWS_SIGN_PFX_PASSWORD` are set, signtool signs the exe (SHA-256, RFC 3161 timestamp); else if `SIGNPATH_API_TOKEN`/`SIGNPATH_ORGANIZATION_ID` are set, the SignPath action does; runs `iscc` (Inno Setup preinstalled on the image, or installed by `windows-build` and passed as an artifact, never by choco in this job), signs the setup exe the same way, writes minisign `.minisig` files with the trusted comment from 5g when `UPDATE_SIGNING_KEY` is set, and sets output `signed=true|false`.
  - Split scripts/bundle-windows.ps1 into `-Build` and `-Package` modes to match.
  - Pin every third-party action in these jobs (SignPath and any other non-`actions/` action) by full commit SHA with the version in a comment.
  - The `release` job downloads the `windows-package` artifact too and includes it in SHA256SUMS.
done-when: `ruby -ryaml -e 'YAML.load_file(".github/workflows/release.yml")'`; jobs windows-build and windows-package exist, only windows-package has environment: release, and release needs windows-package
needs: 6a, 0c
difficulty: medium
kind: change

## 6c winget publishing from CI
files: .github/workflows/release.yml, packaging/winget/
do: - Job `winget` after `release` (its own environment `winget`, so the PAT is not visible to the signing job): runs only when `windows-package` reported `signed=true` and the secret `WINGET_TOKEN` (classic PAT with public_repo, owner of a fork of microsoft/winget-pkgs) exists. Uses `vedantmgoyal9/winget-releaser`, pinned by commit SHA (v2 in a comment), with identifier `avbel.Vaultkeeper`, `installers-regex: '-x64-setup\.exe$'`, `version` from the tag without `v`.
  - packaging/winget/: the manifests for the first, manual submission (winget-releaser only updates an existing package): version, installer (InstallerType inno, Scope user, Architecture x64, MinimumOSVersion 10.0.26100.0, UpgradeBehavior install, Commands vaultkeeper) and defaultLocale (Publisher, License GPL-3.0-only, ShortDescription), plus a README with the one-time `komac new` or `wingetcreate` command.
done-when: `ruby -ryaml -e 'YAML.load_file(".github/workflows/release.yml"); Dir["packaging/winget/*.yaml"].each { |f| YAML.load_file(f) }'`
needs: 6b
difficulty: medium
kind: change

## 7a Windows test checklist and memory measurement
files: docs/solutions/windows-test-checklist.md, scripts/measure-windows.ps1
do: - Checklist for the user's Win11 24H2+ PC, one line per risk in windows-support.md §10 that applies to x64: Hello spike outputs (4a), Hello after PIN reset, removal, RDP; hardening with Defender plus any third-party AV, CJK IME, Narrator/NVDA, file dialog with OneDrive (then decide on `VAULTKEEPER_STRICT_MITIGATIONS` defaults); pipe squatting (start a fake server first, expect refusal); console policy in cmd, PowerShell, Windows Terminal, interactive and piped; Chromium via cmd.exe and Firefox; security key via webauthn.dll; tray sharpness at 100–200 %; daemon surviving the browser host exit; the hardened daemon still shows in Task Manager with its image path and `vaultkeeper --quit` can wait for it (SYNCHRONIZE); a second Vaultkeeper in an RDP session of the same user gets the "already running" message; installer install/upgrade/uninstall, self-update from a signed release, and winget install; SmartScreen with a signed build.
  - scripts/measure-windows.ps1: private working set of the daemon tray-only, UI with a window shown, and UI 10 s after the window closed, printed next to the macOS step-0 numbers (13.9 / 47.3 / 41.8 MB).
done-when: both files exist
needs: 0a
difficulty: easy
kind: change

## 7b Docs: Windows status
files: docs/solutions/windows-support.md, docs/USAGE.md
do: Add a short "Implementation" section at the top of windows-support.md linking to .plan/windows-support.md and the checklist, mark ARM64 as out of scope (§9), and record decided items (Inno per-user, optional signing, winget from CI, Ctrl+Shift+Space default, capture exclusion on by default). Do not touch README.md.
done-when: `grep -q "Implementation" docs/solutions/windows-support.md`
needs: 6c
difficulty: easy
kind: change

## 7c Review of all Windows changes
files: .plan/windows-support.md
do: Done by the orchestrator: a review agent on Opus at xhigh effort (one-time exception the user approved) reviews `git diff main...windows-support` for correctness, security and macOS regressions; fix CRITICAL and HIGH findings before 8a.
done-when: review findings addressed
needs: 7b
difficulty: easy
kind: change

## 8a Pull request and CI check
files: .plan/windows-support.md
do: Done by the orchestrator, not a worker: after the last phase commit is pushed to `windows-support`, open a PR to main and confirm every Windows job in ci.yml passes; fix failures before calling the work done.
done-when: `gh pr checks --watch` reports all checks passing
needs: 7b
difficulty: easy
kind: change

## 1p Sealed store lifecycle tests through the vault
files: crates/vault/tests/sealed_lifecycle.rs, crates/vault/tests/common/
do: Integration tests that run the real vault (the existing mock-server helpers in crates/vault/tests) with a `SealedFileStore` over a temp dir instead of `MemorySecretStore`: login → lock → unlock → sync reads the refresh token; login → logout leaves no `.enc` files for that account; account switch keeps the other account's files and they reopen after switching back; overwriting the refresh-token file with one sealed under another user key → next sync reports the log-in-again outcome and the file is gone. Reuse the existing test fixtures; no production code changes unless a test exposes a bug.
done-when: `cargo test -p vk-vault --test sealed_lifecycle`; `cargo clippy -p vk-vault --all-targets -- -D warnings`
needs: 1m
difficulty: medium
kind: change

## 3m Log files on Windows
files: app/src/os/log_file.rs
do: `log_dir()` on Windows returns `%LOCALAPPDATA%\Vaultkeeper\logs` (from `vk_platform::paths` data dir's parent logic or `ProjectDirs::data_local_dir()`), created with the private-dir helper; the macOS `~/Library/Logs/vaultkeeper` path and the vw-it override stay unchanged. Unix-only mode code stays `cfg(unix)`.
done-when: `scripts/check-windows.sh -p vaultkeeper --all-targets`; `cargo test -p vaultkeeper log_file`
needs: 1o
difficulty: easy
kind: change

## Status (stopped 2026-11-15 on user request)
Done and pushed to `windows-support` (last commit 1e31838): every code step 0a–6c, 7a, 7b; the Opus xhigh review (7c) and all its fixes except the ones below. Last full Windows CI with green results: 9370fbc; the run for 1e31838 (review fixes + 26 app-test expectation fixes) was started but not checked.
Next, in order:
- Check CI for 1e31838 (`gh run list --branch windows-support`); fix any Windows failures.
- Hotkey display on Windows: Settings shows macOS symbols ("⌃⇧Space") and the recorder says "Add ⌘, ⌥ or ⌃"; show "Ctrl+Shift+Space" style on Windows (tests in app/tests/hotkey_recorder.rs and generator_settings.rs pin the current strings).
- Native messaging registry has no Windows test (app/src/os/browser/windows.rs); add tests under a throwaway HKCU\Software\VaultkeeperTest-* base.
- Known limitations to state in the PR: auto-type restores the target app's top window, not the exact HWND; browser signer allowlist is name-only; mio slot reset relies on mio internals (keep mio pinned); single-instance ack flush can stall on a stalled verified client.
- User's manual Windows test pass (docs/solutions/windows-testing-guide.md), Hello spike output → correct passport.rs if needed.
- 8a: open the PR to main once Windows CI is green.

## 9a ARM64 Windows builds
files: .cargo/config.toml, scripts/check-windows.sh, .github/workflows/, scripts/bundle-windows.ps1, packaging/windows/, packaging/winget/, app/src/daemon/update/, docs/solutions/
do: The user reversed "x64 only": their test laptop is Windows 11 on ARM64. Add `aarch64-pc-windows-msvc` everywhere x64 exists: target rustflags (no x86-64-v2, no /CETCOMPAT), the cross-check script, CI build+test on `windows-11-arm`, release build/package per arch, an ARM64 Inno installer, updater asset selection by arch, winget manifests with both installers, and docs.
done-when: `scripts/check-windows.sh --workspace --all-targets`; `VK_WIN_TARGET=aarch64-pc-windows-msvc scripts/check-windows.sh --workspace --all-targets`; `cargo test -p vaultkeeper update`
needs: 6c
difficulty: medium
kind: change
