# vaultkeeper — lightweight Rust desktop client for Vaultwarden

## Context
The official Bitwarden desktop app (`../clients/apps/desktop`) is Electron + Angular. It uses a lot of RAM, hides
"copy password / copy OTP" in menus, and carries many features that only matter for Bitwarden's cloud.
Goal: a small GPL-3.0 Rust app for a self-hosted Vaultwarden that covers:
- the vault basics, including the password generator;
- an SSH agent;
- living in the tray, with optional autostart and an optional unlock prompt at launch;
- low RAM use;
- a new UI with one-click copy and light/dark themes.

The repo `vaultkeeper` is empty (no commits yet). Step 1 copies this document to
`docs/solutions/vaultkeeper-architecture.md`.

## Decisions (agreed)
- **License:** GPL-3.0.
- **UI toolkit:** Slint.
- **Platform:** macOS first. The core crates stay cross-platform.
- **Unlock in v1:** master password + **hardware-enforced Touch ID**. There is no Apple Developer account, and none is needed.
  - The app creates a CryptoKit `SecureEnclave.P256.KeyAgreement.PrivateKey` with access control
    `[.privateKeyUsage, .biometryCurrentSet]`.
  - Its `dataRepresentation` is an opaque blob that only this Mac's Secure Enclave can use. We store it in a file;
    no keychain entitlement or provisioning profile is involved.
    Prior art: `remko/age-plugin-se`, an unsigned Homebrew CLI that uses Touch ID-gated Secure Enclave keys.
  - Enrolment (in Rust, with the `p256` crate): ephemeral P-256 key → ECDH with the Secure Enclave public key →
    HKDF-SHA256 → AES-256-GCM-wrap the user key.
  - Unlock: Secure Enclave ECDH (this step shows the Touch ID prompt) → unwrap the user key.
  - A fingerprint change invalidates the key by design. The app falls back to the master password and offers to enroll again.
  - The setting "Require master password on app start" defaults to off, so autostart + unlock-on-start is a single Touch ID touch.
  - PIN comes later.
- **SSH + Touch ID:** an optional setting, global or per key, that makes a sign request need Touch ID
  (an `LAContext` biometrics check) instead of or as well as the Approve button.
- **Browser integration (Chrome, Firefox):** see `BROWSERS.md` for the plan and verified facts.
  - D1: the native messaging host is the same `vaultkeeper` binary in a host mode, so the daemon admits it by cdhash.
  - D2: a second socket, `browser.sock`, with its own narrow protocol; `ui.sock` is never exposed to browsers.
  - D3: the picker is a native window; the extension never receives a list of logins and a credential leaves the app only after a click there.
  - D4: a credential is released for one item, one origin and one request; there is no list, search or get-by-id.
  - D5: pairing per browser profile with a P-256 key made in the extension; the app stores only public keys.
- **No sdk-internal dependency.** The crypto and API code is our own, ported from rbw (MIT, which can be relicensed under GPL).
  The sdk-internal crates are marked "internal, unstable", and their models follow the official server.

## Research facts (verified)
- **Vaultwarden** (checked in the `dani-garcia/vaultwarden` source):
  - Serves both `/identity/accounts/prelogin` and `/accounts/prelogin/password`.
  - The cipher model has `key: Option<String>` (per-item key) and `ssh_key`.
  - The token response includes `AccountKeys` and `UserDecryptionOptions`.
  - 2FA is reported in `TwoFactorProviders2`.
- **rbw** (`doy/rbw`, MIT) already implements: prelogin, login, 2FA email, sync, add/edit/remove cipher, folders,
  refresh token, Argon2id, per-cipher keys and SSH keys. Port from `src/api.rs`, `src/cipherstring.rs` and its
  identity/KDF code.
- **Reusable `desktop_native` crates** (GPL-3.0, in `../clients/apps/desktop/desktop_native`):
  - `ssh_agent`:
    - Reuse as-is.
    - We implement `ApprovalRequester` and call `replace(keys)`.
    - Ed25519, RSA and ECDSA are supported, OpenSSH private keys only.
    - The socket path comes from `BITWARDEN_SSH_AUTH_SOCK`, otherwise `~/.bitwarden-ssh-agent.sock`.
  - `secure_memory` (`EncryptedMemoryStore`): reuse as-is.
  - `core/src/password/macos.rs`: copy as a reference for the keychain code.
- **Protocol and crypto contract to implement:**
  - KDF: PBKDF2-SHA256, or Argon2id with salt = SHA-256(email).
  - `masterPasswordHash` = PBKDF2(masterKey, password, 1 iteration).
  - Key stretching: HKDF-Expand with info "enc" and "mac".
  - EncString formats: type 2 (AES-CBC + HMAC) for read and write; type 0 decrypt only; type 4 (RSA-OAEP-SHA1)
    for org keys.
  - Cipher types 1–5. Types 6–8 are shown as "unsupported".
  - 2FA providers: 0 (authenticator), 1 (email), 5 (remember), 8 (recovery code).
  - TOTP formats: bare base32, `otpauth://` and `steam://`.
  - Generator: the EFF long wordlist (copy from `libs/tools/generator/core/src/metadata/password/eff-word-list.ts`).
- **RAM:** the only benchmark found was a stress test. It measured Slint at about 92–130 MB, egui 94–157, iced 86–177
  and Tauri 250–740. Freeing the window's memory when it closes is the key point for tray mode, and it has not been
  measured yet. Step 0 measures it.

## Architecture
```
Cargo workspace (GPL-3.0, edition 2024, tokio)
crates/core      crypto (KDF, keys, EncString; Zeroizing key types)
                 api    (reqwest+rustls client, serde models with PascalCase/camelCase aliases)
                 vault  (session state machine, encrypted on-disk cache, decrypt-on-demand views, search, CRUD)
                 totp, generator (pure)
crates/ssh       adapter over vendor/ssh_agent: ApprovalRequester -> channel to UI; key import (PEM/PKCS8 -> OpenSSH via ssh-key)
crates/platform  keychain (security-framework), Touch ID: a small Swift shim (CryptoKit SecureEnclave; generate and ECDH only,
                 linked through the swift-rs crate, ~80 lines) plus an objc2-local-authentication LAContext check for SSH approvals,
                 autostart (auto-launch,
                 LaunchAgent), clipboard (arboard + exclude_from_history + auto-clear), single instance (interprocess),
                 hardening (PT_DENY_ATTACH, RLIMIT_CORE=0), sleep/screen-lock events
app/             vaultkeeper binary: Slint ≥1.17 UI (built-in SystemTrayIcon, no tray-icon crate) + global-hotkey; owns the tokio runtime on a background thread,
                 calls back to the UI with slint::invoke_from_event_loop
vendor/ssh_agent, vendor/secure_memory   copied from ../clients with the upstream commit recorded; any patch is minimal and documented
```

**Key design points**
- **Lock state:** LoggedOut → Locked → Unlocked.
  - Lock happens on: a timeout, system sleep or screen lock, or manually.
  - Locking zeroizes the user key, org keys and the decrypted list fields.
- **Disk cache.** The sync response is stored as received, so the fields stay EncStrings.
  - Location: `~/Library/Application Support/vaultkeeper/`, mode 0600, written atomically.
  - The protected user key and the KDF settings are stored too, so unlocking works offline.
  - The refresh token and the Touch ID user key go in the keychain.
- **Decrypt on demand.** Unlock decrypts only names, usernames, URIs and folder names, which is what the list and search need.
  Passwords, TOTP secrets, notes and card data are decrypted when used, held as `Zeroizing`, and dropped right away.
  This keeps both RAM and the amount of plaintext in memory down.
- **SSH agent.**
  - Keys are pushed to the agent after unlock and on every sync.
  - Lock, log out and account switch clear them and reset the agent's store to "uninitialized" (a vendored
    `clear()`, see `vendor/PATCHES.md`). The next `ssh-add -l` or connection then asks for list approval, which opens
    the lock screen and answers once the vault is unlocked with the keys loaded. A locked vault serves no keys.
  - Each sign request opens an approval window.
  - With "SSH requires Touch ID" on, the daemon shows the Touch ID prompt itself after the UI approves (one prompt at a
    time, for that request only). An `approved` from the UI alone cannot sign.
  - Approval can be remembered until the next lock, as in the official app; a remembered key skips the UI and Touch ID.
    It is remembered only after Touch ID passed.
- **Sync.** Runs on unlock, every 30 minutes, and on demand. A websocket live-sync comes later.
- **UI (Fable design).** Two surfaces sharing one set of view models:
  - **Quick Panel:** a search-first pop-up opened by a global hotkey (default ⌘⇧Space) or a tray click.
    - Shows 8 rows.
    - Keys: Enter copies the password, ⇧Enter the username, ⌘Enter the TOTP.
    - It hides when it loses focus.
  - **Manager window:** two panes (list | detail), with filter chips instead of a permanent sidebar.
  - **List rows:** every row has one-click copy buttons that are always visible.
    - A login row has buttons for username, password and TOTP.
    - The TOTP code is shown in monospace with a 12 px countdown ring that turns to the warning colour under 5 s.
    - The buttons change per type: card, identity, SSH key, note.
  - **Lock screen** and an **SSH approval window** (shows the process and the key fingerprint, auto-denies after 30 s).
  - **Generator** for passwords and passphrases.
  - **Theme:** design tokens for light and dark. It follows the system by default and can be overridden.
  - **Copy feedback:** a ✓ on the button, a footer reading "Copied · clears in 30s", and a drain bar.
- **Tray and autostart.**
  - Tray menu: Quick search, Open vault, Generator, Lock/Unlock, Sync now, Quit.
  - No Dock icon unless the Manager window is open (activation policy Accessory or Regular).
  - Autostart installs a LaunchAgent that runs `vaultkeeper --tray`.
  - The "Ask to unlock on start" setting shows the lock window at launch.
- **Clipboard.** Content is marked concealed (`org.nspasteboard.ConcealedType`). It is cleared after N seconds
  (default 30), but only if the clipboard still holds our value.

## Open questions (each blocks only the step that depends on it)
- **Process model.** Step 0 decides between one process and a background process plus a separate window process.
  - Rule: if RSS after the window is dropped is ≤ tray-only RSS + 15 MB, use one process.
  - Otherwise the background process owns core, the SSH agent and the tray.
  - The window process then talks to it over a 0600 local socket and exits when its window closes.
  - Only step 9 depends on this.
- **Minimum Vaultwarden version.** It must support the SshKey cipher type. Check against the user's server in step 7.

## Build plan
Parallelism: once steps 0 and 1 are done, steps 2–6 and 8 are disjoint modules or crates and run as concurrent agents
(Sonnet). Each agent gets its step verbatim, the Decisions and Architecture sections, and the rule: do not weaken tests,
do not add dependencies beyond the plan, report blockers instead of working around them. A join check
(`cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings`) runs after each batch.
Commits go through a Haiku agent, with no co-author lines and no new branches.

0. **Spike: Slint RAM** (`experiments/slint-ram/`, gitignored, never committed). Parallel with step 1.
   - Build: a tray icon plus a window with a 400-row list.
   - Measure `footprint`/RSS in four states: tray only; window open; window hidden; window component dropped.
   - Try both renderers (femtovg and software).
   - Done when: the numbers are recorded in `docs/solutions/vaultkeeper-architecture.md` and the process model is decided.
0b. **Spike: Secure Enclave + Touch ID without an account** (`experiments/se-touchid/`). Parallel with steps 0 and 1.
   - Build a Rust binary with the swift-rs shim, ad-hoc signed inside a minimal `.app`.
   - It generates a Secure Enclave key with `.biometryCurrentSet`, wraps 64 random bytes, then unwraps them after a Touch ID prompt.
   - Check that it fails after a fingerprint is added or removed, and that the blob can't be used on another Mac or user account.
   - Done when: wrap/unwrap works from both a plain `cargo run` binary and the ad-hoc signed `.app`.
1. **Scaffold and contracts.**
   - Create the workspace, LICENSE (GPL-3.0), `.gitignore` (including `experiments/`) and rustfmt/clippy config.
   - Vendor `ssh_agent` and `secure_memory` from `../clients/apps/desktop/desktop_native` and record the upstream commit.
   - Write the solution doc.
   - Write the shared contracts as stubs:
     - `core::crypto` public signatures;
     - `core::vault::ItemSummary` / `ItemDetail` view types;
     - the `VaultService` trait the UI calls.
   - Done when: `cargo build --workspace && cargo test --workspace` passes.
2. **`core::crypto`** — KDF, stretching, EncString parse/serialize/encrypt/decrypt (types 2, 0 and 4), RSA private key, Zeroizing types.
   - Port from rbw.
   - Tests use upstream test vectors (rbw and sdk-internal tests), never values computed by our own code.
   - Includes tampered-MAC and wrong-key failure cases.
   - parallel-ok. Done when: `cargo test -p vk-core crypto` passes.
3. **`core::totp` + `core::generator`.**
   - TOTP: RFC 6238 test vectors (SHA1, SHA256, SHA512), a steam vector, otpauth parsing.
   - Generator: length and charset rules, minimum-count rules, a 7776-word list, OsRng.
   - parallel-ok. Done when: `cargo test -p vk-core totp generator` passes.
4. **`core::api`.**
   - Models, plus endpoints: prelogin, token (password grant, 2FA 0/1/5/8, optional `newDeviceOtp`), refresh, sync,
     cipher create/update/soft-delete/restore/delete, folder CRUD.
   - Contract tests use wiremock with JSON fixtures captured from a real Vaultwarden (docker `vaultwarden/server`).
   - Uses only the crypto signatures from step 1. parallel-ok.
   - Done when: `cargo test -p vk-core api` passes.
5. **`crates/ssh`.**
   - Adapter over the vendored agent:
     - socket at `~/Library/Application Support/vaultkeeper/ssh-agent.sock`, using a minimal vendored patch or the env var;
     - an ApprovalRequester backed by a channel;
     - key import and conversion.
   - Integration test: start the agent with an auto-approve stub, then `ssh-add -l` and `ssh-keygen -Y sign` against the socket.
   - parallel-ok. Done when: `cargo test -p vk-ssh` passes.
6. **`crates/platform`.**
   - Keychain, Touch ID, autostart, clipboard with auto-clear, single instance, hardening, sleep/lock events.
   - Touch ID: the Secure Enclave shim from step 0b, enroll/unlock/invalidate, and the `LAContext` check for SSH approvals.
   - Unit-test the clipboard clear rule against a fake clipboard.
   - Unit-test the user-key wrapping round-trip, using a software P-256 key in place of the Secure Enclave.
   - Touch ID and autostart are checked by hand.
   - Depends on: 0b.
   - parallel-ok. Done when: `cargo test -p vk-platform` passes.
7. **`core::vault`.**
   - Session state machine, disk cache, offline unlock, decrypt-on-demand, search, CRUD (new items get a per-item key),
     lock with zeroize.
   - Integration test (`--features vw-it`) against docker Vaultwarden. Register via the API, then login → create →
     sync → decrypt → edit → delete.
   - Round-trip with the official web vault: an item created here must be readable there, and the reverse.
   - Depends on: 2, 4. Done when: `cargo test -p vk-core --features vw-it vault` passes.
8. **UI shell (Slint) on mock data.**
   - Theme tokens, lock screen, Manager window, row component with one-click copy and the TOTP ring, Quick Panel,
     generator view, SSH approval window, settings.
   - Built against `VaultService` with a mock implementation.
   - A few interaction tests with Slint's testing backend.
   - parallel-ok. Done when: `cargo test -p vaultkeeper`, plus `cargo run -p vaultkeeper -- --mock` and screenshots in both themes.
9. **Integration.**
   - Wire the UI to `vault`, `ssh` and `platform`.
   - Login and 2FA screens, tray menu, global hotkey, autostart and unlock-on-start settings, lock timeout, sync timer.
   - Follow the process model from step 0.
   - Depends on: 0, 5, 6, 7, 8.
   - Done when: the manual test script below passes against local docker Vaultwarden and the user's server.
10. **Packaging.**
    - `.app` bundle (cargo-packager), `LSUIElement`, LaunchAgent.
    - Codesign with a **local self-signed code-signing certificate** (free, created once in Keychain Access) instead of an
      ad-hoc signature.
    - Why: it keeps the app's code identity the same across rebuilds, so the keychain item holding the refresh token
      doesn't trigger an "allow access" prompt after every update.
    - Always with the hardened runtime (`--options runtime`) and no entitlements. dyld then ignores `DYLD_*` variables
      and library validation refuses foreign dylibs, so the bundled binary cannot be run with injected code. The IPC
      peer check relies on this. Checked 2026-11-09: a constructor dylib loads into the cargo-built binary but not into
      the bundle.
    - Depends on: 9.
    - Done when: after install and a log-out/log-in, only the tray icon appears; the unlock prompt appears when
      enabled; RSS is in the expected range.

**Later:** browser-extension bridge module (`core::ipc` + `proxy` from desktop_native), PIN unlock,
Linux/Windows (Linux: desktop_native `biometric` with polkit; Windows: Windows Hello), websocket live sync, attachments.

## Verification (end-to-end, manual script for step 9/10)
1. Start Vaultwarden with `docker run -e SIGNUPS_ALLOWED=true vaultwarden/server`. Register in the web vault, enable
   TOTP 2FA, and add a login with TOTP, a card, a note and an SSH key.
2. In vaultkeeper, log in with the 2FA code. Check that the list shows every item type.
3. One-click copy password and copy TOTP from a list row. Paste, and check that the clipboard clears after 30 s.
4. Open the Quick Panel with ⌘⇧Space: type, press Enter, paste. Check that it hides.
5. Create and edit an item in vaultkeeper, then check it in the web vault. Edit it in the web vault, sync vaultkeeper, check again.
6. `SSH_AUTH_SOCK=… ssh-add -l` lists the key. `ssh -T git@github.com` (or `ssh-keygen -Y sign`) opens the approval
   window. Deny makes it fail; approve makes it succeed.
7. Lock (manually and by timeout), then unlock with the master password while offline, then with Touch ID.
   - Add a fingerprint, then check that Touch ID unlock is refused and that the master password re-enrolls it.
   - With "SSH requires Touch ID" on, a sign request shows the Touch ID prompt.
8. Switch themes (system, light, dark).
9. Enable autostart and "ask to unlock on start", log out of macOS and back in. Only the tray icon appears and the
   lock window shows.
10. Check RAM with `footprint vaultkeeper` in four states: tray-only locked, tray-only unlocked, Manager window open,
    after the window closes.

## Risks
- **Slint does not release window memory.** Step 0 measures it before any UI work, and the two-process design is the
  fallback.
- **Crypto or protocol mismatch would corrupt data.** Mitigations:
  - upstream test vectors;
  - the docker Vaultwarden integration test;
  - the web-vault round-trip in both directions before trusting writes;
  - writes always send `lastKnownRevisionDate`.
- **Secure Enclave without signing turns out not to work** (for example a future macOS change). Step 0b checks this first.
  - Fallback: store the user key in a keychain item tied to our self-signed certificate, plus an `LAContext` Touch ID prompt.
  - That is not hardware-enforced, but it's still stronger than the official app.
- **Touch ID prompt phishing.** Any process that copies the Secure Enclave blob can trigger a Touch ID prompt with its own
  text. The user still has to touch, and the blob is useless off this Mac and user account. The blob file is mode 0600,
  and we document this.

## Additional requirements (agreed during implementation)
- **Latest stable Rust (1.99.1) and latest crate versions.** The vendored `ssh_agent` keeps its upstream pins
  (`ssh-key =0.6.7`, `rsa =0.9.6`), and `vk-ssh` uses the same `ssh-key` so parsed keys are interchangeable.
- **Crate split.** The planned `core` crate is split into `vk-crypto`, `vk-api`, `vk-gen` (TOTP and generator) and
  `vk-vault`. The boundaries are cleaner, and parallel work can't break another crate's build.
- **RAM and performance first:**
  - decrypt on demand;
  - `Arc<str>` in list rows, shared rather than copied;
  - search runs over precomputed lowercase text;
  - a periodic UI timer only while a window with visible TOTP rows is open;
  - no timers in tray-only mode.
- **Tests cover the code and every user scenario:**
  - unit tests per crate;
  - Vaultwarden-in-docker integration tests for each vault scenario (login with and without 2FA, offline unlock,
    sync, CRUD, trash and restore, folders, org items, the SSH key flow);
  - Slint testing-backend tests for each UI flow.
- **Server sync:**
  - on unlock, every 30 minutes, on demand, and after every write;
  - optimistic concurrency through `lastKnownRevisionDate`;
  - live websocket sync later.
- **Offline mode.** If the server is unreachable, the cached vault stays usable read-only. When the UI opens it shows an
  "Offline mode" toast, and the next sync that succeeds clears it.
- **Checks before every commit.** `scripts/check.sh` runs `cargo fmt --check` and `cargo clippy -D warnings`. It is wired
  in as `.githooks/pre-commit` (`git config core.hooksPath .githooks`).
- **Recovering from offline mode.**
  - While offline, a background probe calls `GET {base}/alive` with backoff: 5 s, then 10, 20, 40, capped at 60 s.
  - These skip the remaining wait and probe at once: a network-path change, the Mac waking from sleep, and the websocket
    reconnecting successfully.
  - The first success triggers an **immediate full sync**, which clears `is_offline` and makes the UI dismiss the toast.
    The notifications websocket is then reconnected.
  - Tests: a wiremock server that is first down then up, checking that the sync runs without waiting for the 30-minute
    timer; a debounce test so that a burst of triggers produces a single sync.
- **Websocket health.**
  - Every 15 s the client sends a SignalR ping plus a WebSocket ping.
  - If no inbound frame arrives for 35 s, the connection is stale: close it and reconnect.
  - Closes, protocol errors and a 10 s handshake timeout are handled the same way.
  - Reconnects back off at 1, 2, 4 … 60 s. The backoff resets after a connection has stayed healthy for 60 s.
  - Every successful reconnect triggers an immediate full sync, because events may have been missed.
  - Waking from sleep forces a reconnect.
- **Sleep.** When the system goes to sleep, the vault cancels the websocket task and the offline probes, and runs no
  syncs. On wake it reconnects the websocket and runs an immediate full sync. The platform layer supplies the
  sleep/wake events.
- **Attachments, same as the official app.**
  - The model: `cipher.attachments[] {id, url, fileName (EncString), key (EncString of a 64-byte attachment key under
    the cipher key), size}`.
  - The file body is an EncArrayBuffer: byte 0 = type 2, then 16 bytes of IV, 32 bytes of MAC, then the AES-CBC
    ciphertext. The MAC is HMAC-SHA256 over iv‖ct.
  - Upload: `POST /api/ciphers/{id}/attachment/v2 {key, fileName, fileSize}` returns `{attachmentId, url}`. Then
    POST the multipart `data` to `/api/ciphers/{id}/attachment/{attachmentId}`.
  - Download: `GET /api/ciphers/{id}/attachment/{aid}` returns `{url, key, fileName}`. Then GET the url.
  - Delete: `DELETE /api/ciphers/{id}/attachment/{aid}`.
  - RAM: neither direction holds the file in memory. Download streams to a temp file while computing the MAC, verifies
    it, then decrypts to the destination in a second streaming pass. Upload encrypts while streaming.
- **Multiple accounts, log out and switching.**
  - Accounts are saved under `data_dir/accounts/<user_id>/`. Each has its own server, email, cache, tokens (keychain
    account `<user_id>`) and Touch ID file.
  - Only one account is unlocked at a time. Switching locks the current account and shows the lock screen for the
    target.
  - Log out removes the account's local data, then activates the most recently used remaining account.
  - The SSH agent serves only the active unlocked account's keys.
- **Log out wipes everything from that account.** It runs every step below even if an earlier one fails, collects the
  errors, and reports them at the end.
  - Cancel the websocket, sync timer and offline probes.
  - Clear the SSH agent's keys.
  - Clear the clipboard if it still holds our value.
  - Zeroize the user and org keys, decrypted rows, drafts and the MRU list.
  - Delete every keychain item for that user id.
  - Delete `accounts/<user_id>/`: cache, settings, Touch ID blob and temp attachment files.
  - Reset all UI models, including detail, search results, the edit form and generator history.
  - Scenario test: log in as A, sync, copy a password, enable Touch ID and SSH, then log out. After that:
    - A's directory no longer exists;
    - `keychain::get` for A returns `None`;
    - `ssh-add -l` lists no keys;
    - the clipboard is empty;
    - `search` returns `LoggedOut`;
    - no string from A's vault is reachable from the UI models;
    - logging in as B shows only B's data.
- **E2E tests** run against `vaultwarden/server:latest` plus Mailpit (`tests/e2e/compose.yaml`, `scripts/e2e.sh`).
  - The user doesn't use authenticator 2FA, so the main login paths under test are no-2FA and email 2FA / new-device
    verification, with codes read from Mailpit.
  - The authenticator provider stays supported, with a single smoke test.
- **Verified on 2026-11-08.** The user ran `touchid_check` and `touchid_check --auth` on their Mac (M-series, Command Line
  Tools only, no Apple Developer account). The Secure Enclave wrap/unwrap behind Touch ID and the plain Touch ID prompt
  both work. Changing the enrolled fingerprints invalidates the key as designed: `--keep`, then a fingerprint change, then `--reuse` prints "invalidated: enroll again".

## Step 0 result: process model = background daemon + on-demand UI process
Measured by the `experiments/slint-ram` spike with Slint 1.18.1, release builds, physical footprint (in MB):

| renderer | A tray only | B window shown | D window dropped +10 s |
|---|---|---|---|
| software | 13.9 | 47.3 | 41.8 |
| femtovg | 13.5 | 65.6 | 58.0 |
| skia (metal) | 14.3 | 246.7 | 218.6 |

The decision rule was D ≤ A + 15 MB. Every renderer fails it (the best, software, leaves +28 MB), so the app is
**split into two processes**. The window memory plateaus, so it is not a leak.

- **`vaultkeeper --daemon`** starts at login.
  - It owns the tray (Slint `SystemTrayIcon`, no windows, no renderer), the Vault, sync and websocket, the SSH agent,
    the clipboard timer, power events and the global hotkey.
  - Activation policy is Accessory, so it has no Dock icon.
- **`vaultkeeper --ui`** is the same binary, spawned by the daemon when needed.
  - It shows the Manager, the Quick Panel, the lock/login screens, the SSH approval prompt and settings.
  - It uses the software renderer only (`renderer-software`, without skia or femtovg).
  - It lingers 120 s after its last window closes, so the Quick Panel opens instantly on repeated use, then exits.
- **IPC**
  - Transport: a unix socket at `data_dir/ui.sock`, mode 0600.
  - The daemon checks the peer's uid (`getpeereid`) and its code identity.
    - It reads the peer's audit token (`LOCAL_PEERTOKEN`) instead of a pid, so connect-then-`exec` cannot race the
      check.
    - It gets the peer's code object with `SecCodeCopyGuestWithAttributes` and checks it with `SecCodeCheckValidity`
      against `cdhash H"…"`, its own cdhash. Only the very same build gets in, and only while its signature is still
      valid. This works the same for ad-hoc, linker-signed and certificate-signed builds.
    - A designated requirement was not used: with the local certificate it would admit anything signed with that
      certificate, and its private key sits in the user's keychain.
    - `vw-it` test builds can still admit any process of the user (`VAULTKEEPER_TEST_ANY_PEER`).
  - No key material crosses the socket.
    - Touch ID enrolment and unlock run in the daemon (`EnrollTouchId` / `UnlockWithTouchId`): it reads the user key
      from its own vault, seals or unseals it, and shows the prompt with its own text.
    - The UI checks only whether the enrolment file exists, and it can delete it.
    - There is no call that returns the user key or SSH private keys; `RemoteVault` answers those `VaultService`
      methods with an error locally.
  - Messages are length-prefixed serde frames.
  - In the UI process, `VaultService` is implemented by an IPC client that proxies to the daemon's real `Vault`.
  - Daemon → UI commands: show Manager, show Quick Panel, show SSH approval, show unlock, state changes.
  - Each SSH approval carries a request id end to end. A reply settles only the request with that id; a repeated or
    late reply is dropped. In the UI, each prompt's buttons, Esc and 30 s timer answer only their own queued request.
  - Decrypted fields cross the socket only when the UI asks for them (reveal, draft, totp).
