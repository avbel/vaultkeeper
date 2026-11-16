# Windows 11 test checklist (24H2+, x64 and ARM64)

Manual checks that need real hardware, one section per risk in `windows-support.md` §10 that applies.
Run them on a Windows 11 24H2 (build 26100) or newer machine (x64 or ARM64), as a normal user (not Administrator), with the
release build from the same commit. The primary test machine is a Snapdragon (ARM64) laptop; use the `arm64` artifacts there.

Record for the run: `winver` build, antivirus products, display scaling, RDP or local session, and the build tag.
Tick each line only after the expected result, and paste outputs (Hello HRESULTs, hardening log lines, the memory
table) into the pull request. Two groups change a default, so their result must be reported before merging:

- **Windows Hello** gates step 4c and tells `biometric.rs` which statuses are `BiometricInvalidated`.
- **Hardening** decides the defaults of `VAULTKEEPER_STRICT_MITIGATIONS` (step 2i) and capture exclusion (3g).

## 0. Setup

- [ ] `winver` reports 24H2, build 26100 or newer; `echo %PROCESSOR_ARCHITECTURE%` is `AMD64` (x64 PC) or `ARM64` (Snapdragon).
- [ ] Use the CI artifact of the commit under test: `vaultkeeper-windows-arm64` on ARM64, `vaultkeeper-windows-x64` on x64 (no Rust needed), or `out\Vaultkeeper-<tag>-<arch>-setup.exe` (signed for the update and SmartScreen
      sections; an unsigned build is fine elsewhere).
- [ ] At least one login saved, CLI access enabled in Settings, and one login allowed for CLI access.
- [ ] Chrome or Edge plus Firefox installed, one FIDO2 security key, and a second local Windows account is not
      needed: RDP to the *same* user is the case that matters.
- [ ] Optional but useful: a second anti-malware product, a CJK IME, Narrator and NVDA.

## 1. Windows Hello (risks 1, 2, 9)

Build `hello_check.exe` natively for your architecture (`cargo build --release -p vk-platform --example hello_check`; the CI
artifact does not include it); run it from a
console so its window can be passed as `NCRYPT_WINDOW_HANDLE_PROPERTY`.

- [ ] On the Snapdragon laptop: run the native ARM64 `hello_check.exe`; face and fingerprint drivers differ from x64 PCs, so
      report the statuses of every enrolled method (face, fingerprint, PIN) separately.
- [ ] `hello_check.exe`: print the key name that worked (`<SID>//Vaultkeeper//Vaultkeeper` or the variant it fell
      back to), whether RSA-OAEP-SHA256 or PKCS#1 v1.5 was accepted (the app uses PKCS#1 v1.5; OAEP is expected to fail), and every HRESULT/NTSTATUS. Expect no error.
- [ ] `hello_check.exe --strict`: same output with `harden_process(Role::Daemon)` applied first. The credential
      broker must still appear; Task Manager must still be able to show the process.
- [ ] App enrolment: "Set up Windows Hello" prompts once, then matrix enrolment works with face, fingerprint and PIN.
- [ ] Unlock with face: one prompt, no `0x80098044`, and no need to click the window first. Then fingerprint, then PIN.
- [ ] Reset the PIN (Settings → Accounts → Sign-in options → "I forgot my PIN") and unlock: the app says "enrol
      again" (`BiometricInvalidated`), not a decrypt error. Re-enrolling works with no master-password prompt.
- [ ] Remove Windows Hello completely (delete all sign-in methods), unlock: "enrol again". Add Hello back, re-enrol.
- [ ] RDP into the same machine as the same user while Vaultkeeper runs in the console session: the Hello button is
      unavailable or the attempt fails as `BiometricFailed`, never `BiometricInvalidated`; master password unlocks.
- [ ] VM without a TPM (optional): software-backed Hello key enrols and unlocks.
- [ ] `hello_check.exe --delete`, then unlock: "enrol again"; re-enrol works.
- [ ] SSH approval with "SSH requires Windows Hello" (4f): the Windows prompt is in front of the UI window; cancel
      denies the `ssh` request; approve signs it.
- [ ] Record the statuses seen for cancel, no-match, lockout and a busy TPM, so §3.2's mapping can be checked.

## 2. Hardening (risks 3, 9, 10)

Run the daemon and UI from the release build, with Windows Defender first.

- [ ] Defender only: daemon starts, tray appears, unlock works, no restarts or hangs; the daemon log has no failing
      mitigation policy except the expected `MicrosoftSignedOnly` with products that inject hooks.
- [ ] Repeat with a third-party antivirus (for example ESET, Bitdefender or Kaspersky): same result; note which
      policies fail and whether the product still scans the data directory.
- [ ] CJK IME (Microsoft Pinyin or Japanese IME): composition works in search, login e-mail and the file dialog.
- [ ] File dialog: choose a file and an export folder inside OneDrive and Dropbox folders; Common Controls v6 and
      shell extensions load.
- [ ] Narrator reads the Quick Panel, login and Settings; NVDA does too (its hooks are the interesting case).
- [ ] Set `VAULTKEEPER_STRICT_MITIGATIONS=1` and repeat the IME, file-dialog, AV and screen-reader checks. Record
      what breaks and report it: that result sets the defaults.
- [ ] Task Manager (normal and elevated) shows the daemon, its image path and the correct user; ending it from Task
      Manager asks for confirmation and works.
- [ ] `vaultkeeper.exe --quit` stops daemon and UI, returns 0, and waits until the processes are gone
      (`PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE` are still granted); `vaultkeeper --tray` starts again.
- [ ] With `VAULTKEEPER_STRICT_MITIGATIONS=1`, `hello_check --strict` and the tray both still work (risk 9).

## 3. Pipes, single instance and RDP (risks 4, 11)

- [ ] Stop Vaultkeeper. Start a fake server on the CLI pipe with the snippet in the appendix, then run
      `vaultkeeper --tray`: it refuses and names `\\.\pipe\vaultkeeper.<SID>.cli`; it never creates a differently
      named pipe. Stop the fake server and start again.
- [ ] With the fake server still running, `vaultkeeper list` fails with "another program is serving Vaultkeeper's
      pipe" (and "restart it" when the path is ours but the file id differs).
- [ ] Pool recycling: run `vaultkeeper list` ten times back to back (more clients than the pool's four instances);
      all succeed, none hangs.
- [ ] Leave one `vaultkeeper list` client idle for 30 s, then run another: the idle one is dropped, the new one works.
- [ ] Browser and CLI pipes served at once: copy a password while a browser fill runs; no connection is starved.
- [ ] RDP: keep Vaultkeeper running locally, connect by RDP as the same user, start Vaultkeeper there: "already
      running" (the `Global\Vaultkeeper-<SID>` mutex), and tray/menu actions reach the console session's daemon.
- [ ] Close or kill the browser that started the daemon through the native host: the daemon survives (no
      kill-on-close job) and the tray keeps working.
- [ ] Unlock via the UI channel only: no `vaultkeeper` window is listening on a named pipe except the CLI, browser,
      instance and SSH names (`Get-ChildItem \\.\pipe\ | Where-Object Name -like 'vaultkeeper*'`).

## 4. Console and CLI (risk 5; open point: AttachConsole)

- [ ] cmd.exe: `vaultkeeper list` prints and the prompt returns; no second console window appears or lingers.
- [ ] Windows PowerShell 5.1 and PowerShell 7: same as cmd.
- [ ] Windows Terminal (with cmd, PowerShell and PowerShell 7 profiles): output appears in the active tab.
- [ ] Interactive and piped: `vaultkeeper list | more`, `vaultkeeper list | findstr x`, `vaultkeeper get K F >
      out.txt`; output goes to the right stream, exit codes are preserved. If interactive output is missing, note
      whether `AttachConsole(ATTACH_PARENT_PROCESS)` fixes it, and report it.
- [ ] Unlock prompt from the CLI: locked vault → the app's unlock window opens, unlock succeeds, the command resumes.
- [ ] From Explorer and the Run dialog (Win+R): `vaultkeeper` and `vaultkeeper --tray` do not flash a console window;
      the window or tray appears.
- [ ] `vaultkeeper --tray` from a terminal detaches; closing the terminal leaves the daemon running.

## 5. Browsers and native messaging (risk 6)

- [ ] Chrome and Edge: the extension connects with the daemon already running, and starts it when it is not.
- [ ] Chromium's default `cmd.exe` parent: the browser is identified (parent chain skips one `cmd.exe`), fill and
      save work, and Settings shows the browser name.
- [ ] If you can set the `NativeHostsExecutablesLaunchDirectly` policy in `chrome://policy`, repeat: still identified.
- [ ] Firefox direct launch: the extension connects and fills.
- [ ] An unknown parent (start the host by hand from a terminal) falls back to today's "unknown browser" handling and
      does not crash.
- [ ] `HKCU\Software\{Google\Chrome,Microsoft\Edge,BraveSoftware\Brave-Browser,Chromium}\NativeMessagingHosts` and
      `HKCU\Software\Mozilla\NativeMessagingHosts` point at the manifest after install; uninstall removes them (§9).

## 6. Security keys (risk 7)

- [ ] 2FA login with a FIDO2 key: Windows shows its own PIN/touch prompt; the login window only says "Follow the
      Windows prompt"; the assertion is accepted.
- [ ] Cancel the Windows prompt: the app shows the cancelled outcome and stays on the 2FA step.
- [ ] Wrong key or wrong PIN: a clear error, then a retry with the right key works.
- [ ] A key registered on macOS works unchanged on Windows (same RP id and credential ids).

## 7. Tray, DPI and window treatment (risk 8; §7.12)

- [ ] At 100, 125, 150 and 200 % scaling the tray glyph is sharp and the keyhole is readable, for Blue (default),
      Auto, White and Black.
- [ ] Auto follows the taskbar theme (light taskbar → Black, dark → White), including "Show accent colour on Start
      and taskbar"; High Contrast follows the system colours.
- [ ] The icon starts in the overflow flyout; after pinning it stays across a restart. `explorer.exe` restart brings
      the icon back.
- [ ] Capture exclusion on (default): Quick Panel and Manager are absent from Snipping Tool stills/recording and from
      Recall snapshots. Turned off: they appear.
- [ ] Quick Panel opens on the monitor under the cursor with the right DPI, has no taskbar button; the Manager has one.
- [ ] The hotkey's last input wins the foreground: after closing the panel the previously focused window regains
      focus, and auto-type types into it (see §8).

## 8. Clipboard, hotkey, autostart, session events (§7.3, §7.4, §7.6)

- [ ] Copy a secret: Win+V history contains no entry, and a second machine signed into the same Microsoft account
      does not receive it through cloud clipboard; the auto-clear rule still empties the clipboard.
- [ ] Default hotkey Ctrl+Shift+Space opens the Quick Panel (⌘⇧Space is macOS only).
- [ ] Auto-type into Notepad and a browser field types the value once; into an elevated Notepad it fails with the
      "could not type" reason (UIPI), not a silent no-op.
- [ ] Autostart: enabling writes `"<install dir>\vaultkeeper.exe" --tray` under `HKCU\...\CurrentVersion\Run`; turning
      it off in Settings → Apps → Startup is reported as off by Vaultkeeper; a moved exe path is rewritten.
- [ ] Win+L locks the session and the vault; sleep and resume keep it locked until unlocked.
- [ ] Log off and shut down with the vault unlocked: no lost writes, the vault locks and flushes (SessionEnding).

## 9. Installer, update, winget, SmartScreen

- [ ] Fresh per-user install: no UAC prompt, target `%LOCALAPPDATA%\Programs\Vaultkeeper`, Start menu shortcut,
      Add/Remove Programs entry, install directory on the user `PATH` in a newly opened terminal, tray starts.
- [ ] Upgrade over the previous release while the daemon runs: `--quit` runs and is waited for, files are replaced,
      the version in Add/Remove Programs and `vaultkeeper --version` match, data survives, tray restarts.
- [ ] Uninstall: daemon stopped, Run value, native-messaging keys, shortcut and `PATH` entry removed;
      `%LOCALAPPDATA%\vaultkeeper` (data and logs) stays unless the checkbox is ticked.
- [ ] Self-update from a signed older release to a signed newer one: download, signature and Authenticode checks pass,
      the installer runs silently, the app restarts and Add/Remove Programs shows the new version (so winget sees it).
- [ ] An unsigned build refuses the update and logs the reason; nothing is installed.
- [ ] `winget install avbel.Vaultkeeper`, then `winget upgrade`: version and installer source match the release.
- [ ] SmartScreen with the signed setup as a normal user: no "Windows protected your PC", publisher is the signing
      identity (record whether it is the project's or SignPath's name, which decides where reputation accrues).
- [ ] With Smart App Control on: the signed installer and the installed exe run without a block.

## 10. Memory (rust-high-performance)

- [ ] Run `scripts/measure-windows.ps1` and paste its table. macOS reference (physical footprint, software renderer):
      13.9 / 47.3 / 41.8 MB. Windows measures private working set, so compare shape, not exact bytes; report anything
      above roughly 2× the macOS number with the machine's RAM and graphics configuration.

## Appendix: fake pipe server for the squatting check

Save as `fake-pipe.ps1` and run before starting Vaultkeeper:

```powershell
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$name = "vaultkeeper.$sid.cli"
$pipe = [System.IO.Pipes.NamedPipeServerStream]::new(
    $name,
    [System.IO.Pipes.PipeDirection]::InOut,
    1,
    [System.IO.Pipes.PipeTransmissionMode]::Byte,
    [System.IO.Pipes.PipeOptions]::Asynchronous)
"holding \\.\pipe\$name; press Enter to release"
[void](Read-Host)
$pipe.Dispose()
```

## ARM64 (Snapdragon)

- [ ] `vaultkeeper.exe` is an ARM64 binary (Task Manager, Details: Architecture column, or `dumpbin /headers`: `AA64`).
- [ ] The x64 setup exe refuses to install on this PC; the arm64 one installs, upgrades and uninstalls without UAC.
- [ ] Emulation note: an x64 `vaultkeeper.exe` run under emulation is not a supported configuration; only note Hello,
      tray and hotkey behaviour if you try it, do not file it as a bug.
- [ ] After a signed release, the in-app update downloads `-arm64-setup.exe`, and `winget install avbel.Vaultkeeper` picks the arm64 installer.
