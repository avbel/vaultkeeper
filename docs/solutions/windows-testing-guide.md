# Testing Vaultkeeper on Windows: what and how

A short guide for the manual test pass on a real Windows 11 PC. The detailed checklist with every expected result is
[windows-test-checklist.md](windows-test-checklist.md); this page says how to set up, what is testable at each stage of
the work, and what to send back.

## 1. Getting the build (no Rust needed)

Use a normal (non-administrator) Windows account on Windows 11 24H2 or newer, x64 or ARM64 (a Snapdragon laptop is ARM64). Check with `winver` (build 26100+) and `echo %PROCESSOR_ARCHITECTURE%` (`AMD64` or `ARM64`).
Nothing needs to be installed: GitHub's Windows runner builds everything.

1. In a browser on the PC, sign in to GitHub and open
   <https://github.com/avbel/vaultkeeper/actions/workflows/ci.yml?query=branch%3Awindows-support>.
2. Open the newest run with a green check (or the one I name in the chat).
3. Under **Artifacts**, download **vaultkeeper-windows-arm64** on an ARM laptop (or **vaultkeeper-windows-x64** on an Intel/AMD PC) and extract the zip to a folder, for example
   `C:k-test`. `BUILD.txt` inside says which commit it is.
4. Open PowerShell in that folder (in Explorer: File → Open Windows PowerShell, or right-click → "Open in Terminal").
5. If Windows blocks a file as "downloaded from the internet": right-click it → Properties → tick **Unblock**, or run
   `Get-ChildItem | Unblock-File`. SmartScreen may warn because test builds are unsigned: "More info" → "Run anyway".

The zip contains `vaultkeeper.exe`, `hello_check.exe`, `measure-windows.ps1`, this guide and the checklist. Download
a fresh zip whenever I say a new stage is ready.

## 2. What to send back

For every run, paste into the chat (or the PR):

- the **full console output** of commands that print something;
- what you saw versus what the checklist expects (a phone photo of a prompt is fine);
- after a problem, the log files from `%LOCALAPPDATA%\vaultkeeper\logs` (`daemon.log`, `ui.log`);
- once per machine: `winver` build, antivirus products, display scaling, and whether you were local or over RDP.

## 3. What is testable when

The work lands in phases. I will tell you when a stage is ready; until then, its tests would only show "not built yet".

### Stage A: ready now

**A1. Windows Hello spike** (most important: the real Hello code is written without hardware and will be corrected
from this output). Run from a normal PowerShell or cmd window, not Windows Terminal's admin tab:

```powershell
.\hello_check.exe
.\hello_check.exe --strict
.\hello_check.exe --delete
.\hello_check.exe
```

- The first run creates the key and may show a Windows Hello prompt once, then asks for Hello again to decrypt.
  Use your **face** if you have it, otherwise fingerprint, otherwise PIN.
- Repeat the first command once with each sign-in method you have (face, fingerprint, PIN: on the Hello prompt choose
  "More choices").
- `--strict` runs the same with the daemon's process hardening on.
- `--delete` removes the test key; the run after it must create a new one.
- Each run ends with `RESULT: ok` or `RESULT: failed, last status 0x...`. Paste **all** output of every run.
- If you are willing: reset your Hello PIN (Settings → Accounts → Sign-in options → PIN → "I forgot my PIN"), then run
  the first command again and paste the output. Skip this if the PIN reset is a hassle.

**A2. Windows unit tests**: nothing to do; CI runs them on every push.

### Stage B: the app runs (after phase 3)

Start it from the extracted folder:

```powershell
.\vaultkeeper.exe --tray
```

For the CLI tests either use `.\vaultkeeper.exe list` from that folder, or add the folder to the user PATH once
(Settings → System → About → Advanced system settings → Environment Variables → user `Path` → New) and open a new
terminal.

Then follow the checklist sections in this order (most valuable first):

1. **§4 Console and CLI**: `vaultkeeper list` in cmd, PowerShell and Windows Terminal; piped (`| more`); no console
   window flashes when started from Explorer.
2. **§3 Pipes and single instance**: second start says "already running"; the fake-pipe test from the appendix; ten
   `vaultkeeper list` in a row.
3. **§8 Clipboard, hotkey, autostart, lock**: Win+V shows no copied secret; Ctrl+Shift+Space opens the Quick Panel;
   Win+L locks the vault.
4. **§7 Tray and DPI**: tray icon sharp at 100/150/200 % scaling; Blue/Auto/White/Black.
5. **§2 Hardening**: normal use with Defender; then with `$env:VAULTKEEPER_STRICT_MITIGATIONS = "1"` (Chinese/Japanese
   IME, file dialog in OneDrive, Narrator). This decides the default, so report what breaks.
6. **§10 Memory**: `.\measure-windows.ps1` and paste its table (if PowerShell refuses to run scripts:
   `powershell -ExecutionPolicy Bypass -File .\measure-windows.ps1`).

### Stage C: Hello, auto-type, security keys, browsers (after phases 4–5)

- **§1 Windows Hello in the app**: enrol, unlock with face/fingerprint/PIN, PIN reset → "enrol again", RDP.
- **§8 auto-type** into Notepad and into an elevated Notepad (must say it cannot type).
- **§6 Security keys**: 2FA login with a FIDO2 key through the Windows prompt.
- **§5 Browsers**: Chrome or Edge and Firefox fill and save with the extension.

### Stage D: installer, updates, winget (after phase 6)

- **§9**: install the `Vaultkeeper-<tag>-arm64-setup.exe` (ARM laptop; `-x64-` on an x64 PC) from the GitHub release artifacts (no UAC prompt), upgrade,
  uninstall; self-update and `winget install avbel.Vaultkeeper` only once releases are signed.

## 4. If something goes wrong

- **"Windows protected your PC"**: the test build is unsigned; "More info" → "Run anyway". Smart App Control, if on,
  may block it completely; tell me, and I will look at signing earlier.
- **"another program is serving Vaultkeeper's pipe" or "already running"**: run `.\vaultkeeper.exe --quit`, or end
  `vaultkeeper.exe` in Task Manager, then start again.
- **"Windows' OpenSSH Authentication Agent is already running"**: Services → OpenSSH Authentication Agent → Stop,
  and set Startup type to Disabled (or turn off Vaultkeeper's SSH agent in Settings).
  Vaultkeeper now shows "Windows' OpenSSH Authentication Agent is already running..." in Settings and turns the
  toggle off; in an administrator PowerShell run `Stop-Service ssh-agent; Set-Service ssh-agent -StartupType Disabled`,
  then turn the SSH agent on again.
- **A test leaves the app in a strange state**: quit it, delete `%LOCALAPPDATA%\vaultkeeper` (you will log in again),
  and start over.
