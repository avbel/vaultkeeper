# Browser integration (Chrome and Firefox) — implementation plan

Status: Phases 0–10 implemented and committed (2026-11-11). Chrome was run by hand and the section 11 script passed
(fill, choose another, lock/unlock, save, update, never for this site, other-site confirmation, picker closing on focus
loss, no focus theft by the save prompt, theme switching); Firefox passed the automated run in section 15.
Written 2026-11-10 against commit `d26413c`.

**Handoff: everything is implemented, committed and verified by hand in Chrome. Still unverified: Touch ID before a fill,
real HTTPS sites beyond the ones tried, a normally installed (signed) Firefox add-on, and a Chrome Web Store install.**

- Rust: `scripts/check.sh` (fmt + clippy `-D warnings`) and `cargo test --workspace --no-fail-fast` pass.
  `crates/platform` `single_instance::releasing_the_guard…` is flaky under the full parallel run and passes alone.
- Extension: in `browsers/`, `pnpm exec vp check` (0 errors, 1 false-positive `unbound-method` warning),
  `vp test run` (96 tests), `tsc --noEmit` and `pnpm run build` pass. The Chrome extension id is derived from the
  `key` in `manifest.chrome.json`; the private key is outside the repo (`~/.vaultkeeper-secrets/`, see
  `browsers/README.md`). Copy it if the Chrome id must stay the same on another machine.
- Daemon wiring is in `app/src/daemon/core/browser_glue.rs` (listener lifecycle, `BrowserHost` for the sessions,
  manifests, Touch ID, TOTP copy, activity log `browser.log`, tray line, save queue). Sessions are in
  `app/src/daemon/browser/dispatch.rs`; fill in `fill.rs`; save in `save.rs`; manifests in `manifests.rs`.
- Review fixes applied after an independent read: credential responses are serialised straight into a wiped
  buffer (the host writes stdout unbuffered); cooldown and buckets are per paired key and per canonical origin so a
  reconnect or `HTTPS://Host:443` does not reset them; pairing windows are limited to 3/min; unknown requests get
  an error reply; a panicking fill answers `internal`; a background sync during the picker no longer yields
  `denied`; a trailing dot no longer turns a real domain into an intranet name.
- Changed after the manual run: a lone match on an https page is filled without the picker (setting `browser_fill_single`,
  default on; a deliberate relaxation of D3's "first release needs a click", still gated by the in-page user gesture and by
  Touch ID when that is on), and Touch ID now applies to remembered and single-match fills too.
- Known gaps, none blocking:
  - The save prompt is not placed in the top-right corner of the cursor's screen (needs a new `WindowPlacement`).
  - Whether the real UI process keeps the browser frontmost when the save prompt shows is untested by hand
    (section 8.4); apply the `give_focus_back` fallback if it steals focus.
  - An open Settings window refreshes its "Paired browsers" list only on open and after Remove.
  - The extension has no "TOTP code copied" signal; the daemon copies the code and does not tell the page.
  - Firefox idle-port survival with a normally installed add-on, Firefox key persistence across a restart,
    and whether Firefox's `runtime.id` equals the id the host receives are unverified (section 14).
  - Duplicate save candidates sent while locked each take one of the three queue slots.
  - Brave, Edge and Chromium are out of version 1 (signatures not checked).
- On another computer: `BROWSERS.md` is untracked and `experiments/` is gitignored, so neither travels with `git`.

This document is written for an implementer who has not seen the design discussion. Follow it in phase order. Where it
says **VERIFY**, check the fact against the real system or current vendor docs before writing code that depends on it, and
record the result in the "Verified facts" section at the end.

## 1. Goal and non-goals

Goal: Chrome and Firefox fill logins from Vaultkeeper and offer to save new or changed passwords, while the browser stays a
thin client.

- The extension never logs in, never holds the master password, the user key or a copy of the vault.
- The vault, all matching logic, every decision and every prompt live in the app (the daemon and its `--ui` process).
- The tray app (daemon) must be running; the extension can start it.
- Every native window follows the app style and the app's light/dark theme. The small extension UI uses the same tokens.

Non-goals for this plan: Safari, passkeys (WebAuthn), filling cards and identities, autofill on page load, cross-origin
iframes, Linux and Windows.

## 2. Architecture

```
web page
  │ DOM only
content script (per frame, isolated world)          browsers/src/content/
  │ runtime.sendMessage
background (Chrome: service worker, Firefox: event page)   browsers/src/background/
  │ native messaging: stdio, 4-byte length + JSON
vaultkeeper (host mode, same binary, started by the browser)   app/src/browser_host/
  │ unix socket data_dir/browser.sock: u32 LE length + JSON
vaultkeeper --daemon  → BrowserControl               app/src/daemon/browser/
  │ existing ui.sock (protocol 10): BrowserPrompt events
vaultkeeper --ui      → picker, pair prompt, save prompt (Slint)   app/ui/browser.slint
```

### Decisions (do not change without asking the user)

| # | Decision | Why |
|---|---|---|
| D1 | The native messaging host is the **same `vaultkeeper` binary** in a new host mode, not a second binary. | The daemon admits socket peers by cdhash (`crates/ipc/src/peer.rs`); the same binary passes unchanged. |
| D2 | A **second socket** `browser.sock` with its own protocol. `ui.sock` and its `Call` enum are not exposed to browsers. | `ui.sock` serves one trusted UI and can dump the vault. The browser API must be narrow. |
| D3 | The **picker is a native Slint window**, not an in-page dropdown. The extension never receives a list of logins. | A credential leaves the app only after a click in app UI. This defeats clickjacking, a compromised extension and enumeration. It also gives the app style for free. |
| D4 | A credential is released for **one item, one origin, one request**. There is no "list", "search" or "get by id" request. | Limits what a compromised browser can take. |
| D5 | **Pairing** per browser profile with a P-256 key generated in the extension. The app stores only public keys. | The user consents to each browser once and can revoke it. Nothing secret is added on the app side. |
| D6 | The host **verifies its parent process** is a known browser by code signature and tells the daemon. | Stops scripts and a fake host placed in front of the real one. |
| D7 | Approvals are **remembered per connection, origin and item until lock**. | Second fill on the same site is instant; a new connection (possible attacker) starts with nothing. |
| D8 | Save/update prompts are native. The extension gets **no result** for a save candidate. | No password oracle. |
| D9 | Wire format on both hops is **JSON**. The host relays bytes and does not parse requests. | One parser and one validator, in the daemon. |
| D10 | No autofill on page load. Fill needs a user gesture. | A filled password is readable by page script. |

## 3. Wire protocols

### 3.1 Browser ⇄ host (native messaging)

Standard: each message is a 4-byte **native-endian** length, then UTF-8 JSON. Limits enforced by the host: incoming at most
64 KiB, outgoing at most 64 KiB. A longer message closes the connection. (The browsers allow far more: 1 MB from host
to browser in both, 64 MiB browser to host in Chrome, 4 GB in Firefox. Ours is stricter on purpose.)

The host must write **nothing else to stdout**. All logging goes to stderr and the log file.

### 3.2 Host ⇄ daemon (`browser.sock`)

Frames: u32 little-endian length, then the body. Reuse `vk_ipc::frame::read_frame` for reading. Body limit 64 KiB (a new
constant `BROWSER_MAX_FRAME`, checked after `read_frame`, and the listener closes the connection on a longer frame).

1. First frame from the host: `HostHello` (JSON).
2. First frame from the daemon: `HostWelcome` (JSON) or `HostRefused`, after which the daemon closes.
3. After that every frame is one native message body, relayed unchanged in both directions.

```jsonc
// HostHello
{ "protocol": 1,
  "caller": { "kind": "chromium", "origin": "chrome-extension://<id>/" },   // or
  // "caller": { "kind": "firefox", "extension_id": "browser-extension@vaultkeeper" },
  "parent": { "pid": 812, "executable": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
              "browser": "chrome" } }      // "browser": null when the signature check failed
// HostWelcome
{ "ok": true }
// HostRefused
{ "ok": false, "reason": "disabled" | "version" | "unverified_parent" | "busy" }
```

### 3.3 Extension ⇄ daemon (relayed)

Requests carry a numeric `id` chosen by the extension; the response echoes it. Events have no `id`.

```jsonc
// success                                  // failure
{ "id": 7, "ok": true, "result": { } }      { "id": 7, "ok": false, "error": "<code>" }
```

Error codes (a closed list, serialized snake_case): `bad_request`, `unknown_type`, `unpaired`, `denied`, `cancelled`,
`timeout`, `locked`, `logged_out`, `no_login`, `busy`, `rate_limited`, `insecure_page`, `offline`, `internal`.

| Request `type` | Fields | Result | Notes |
|---|---|---|---|
| `hello` | `protocol: 1`, `extension_version`, `public_key` (base64, 65-byte uncompressed SEC1 P-256) | `challenge` (base64, 32 random bytes), `known: bool` | Must be the first request. |
| `prove` | `signature` (base64, 64 bytes, IEEE P1363 `r‖s`) | `state`, `theme`, `fingerprint` | Must be the second request. Unknown key → native pair prompt before the answer. |
| `status` | — | `state`, `theme` | |
| `fill` | `origin`, `path`, `choose: bool`, `fields: { username: bool, password: bool }` | `username`, `password` (either may be `null`) | Native picker unless remembered. `choose: true` always shows the picker. |
| `save_candidate` | `origin`, `path`, `username` (may be `""`), `password`, `kind: "login" \| "change"` | `{}` always, at once | The daemon decides alone whether to prompt. |
| `unlock` | — | `state` | Shows the lock screen; answers after unlock, cancel or 120 s. |
| `open_app` | `view: "manager" \| "settings"` | `{}` | |

Events: `{ "event": "state", "state": "unlocked" | "locked" | "logged_out", "theme": "light" | "dark" | "system" }`, sent
on every change of either value, only after a successful `prove`.

Signed message for `prove`: the bytes `"vaultkeeper-browser-v1\0"` ‖ challenge (32 raw bytes) ‖ UTF-8 of the caller string
from `HostHello` (`origin` or `extension_id`). ECDSA P-256 with SHA-256.

Fingerprint: SHA-256 of the 65 public-key bytes, first 8 bytes, uppercase hex in four groups: `A1B2-C3D4-E5F6-0718`.

Validation in the daemon (reject with `bad_request`):

- `origin` parses with `url::Url`, scheme is `https` or `http`, has a host, and has no path, query, fragment or credentials
  beyond `/`. Length at most 2048.
- `path` starts with `/`, contains no `?` or `#`, length at most 2048.
- `username` at most 512 bytes, `password` 1 to 4096 bytes.
- Any request other than `hello` before `hello`, or other than `prove` before a successful `prove` → `unpaired`.

Limits per connection: at most 4 connections in total (the fifth gets `HostRefused busy`); one `fill` in flight (a second
gets `busy`); 20 `fill` and 10 `save_candidate` per minute (token bucket, over → `rate_limited`); after 3 `fill` requests
for one origin end in `cancelled`/`timeout` within 60 s, that origin gets `rate_limited` for 60 s.

## 4. Security model

Trust: the daemon and the UI process are trusted. The host is trusted code (same binary, hardened runtime) but its stdin
is not. The extension is semi-trusted: it is the user's browser, but it may be compromised. The web page is hostile.

| Threat | Defence |
|---|---|
| Page script reads the vault | Impossible: the page talks to nobody. Only a filled value is visible to the page it was filled in. |
| Page triggers a fill without the user | Content script accepts only `event.isTrusted` clicks; the first release per origin needs a click in a native window. |
| Phishing site with a similar name | Matching is done in the daemon on the URL the *browser* reports, by Bitwarden URI rules. The picker shows the ASCII (punycode) host. Picking a login saved for another site needs an explicit second confirmation. |
| Clickjacking the in-page icon | A click only opens the native picker. |
| Compromised extension or renderer asks for other sites | It can only make the native picker appear for that origin, with the browser name and host shown. No list, no search, no silent release. Rate limits and a cooldown stop prompt bombing. |
| Local script runs the host binary | D6: parent must be a signed known browser, else `unverified_parent`. Plus D5 pairing. |
| Fake host placed in the native-messaging manifest (man in the middle) | The real host it would have to start has a non-browser parent → refused. The daemon also re-checks its manifests (section 9). |
| Another extension talks to ours | No `externally_connectable`, no `onMessageExternal`; `sender.id` is checked. The native manifest allows one extension id. |
| Tab navigates between request and fill | Background re-reads the tab URL before delivering; content script re-checks `location.origin` and the request nonce. |
| Password oracle through save detection | `save_candidate` always answers `{}` at once (D8). |
| Lock while a prompt is open | The UI closes browser prompts on lock; the daemon re-checks `Unlocked` right before `reveal`. |
| Hostile text in a trusted prompt | Prompts show only: browser name from the verified signature, the ASCII host, and vault item names. Never the tab title or any string from the page or extension, except the username of a save candidate, shown truncated to 64 characters in a monospace field labelled "Username from the page". |

Known limits (state them in `docs/USAGE.md`):

- **Malware running as the same macOS user** can drive a real browser with a copied profile, so pairing and the parent
  check are barriers, not guarantees. What still holds: nothing is released without a click in a native window, and
  remembered approvals belong to one live connection.
- A filled password can be read by scripts of the page it was filled into (XSS on that site).
- JavaScript strings cannot be wiped. The extension keeps a credential only for the duration of one message hand-off.
- The parent check has a known bypass (start the host, then `exec` a browser in the parent). It is kept because it still
  blocks the simple cases and the man-in-the-middle host.

## 5. Phase 0 — verification spikes (no production code)

Do these first; each takes minutes. Put throwaway code in `experiments/` (gitignored).

1. **Parent process.** Register a dummy native host (a shell script that writes `ps -o pid,ppid,comm -p $$ -p $PPID` to a
   file) for Chrome and for Firefox. Confirm the host's parent is the main browser process and not a helper or `sh`.
   If it is a helper, record how many ancestors up the main process is; section 7.3 then walks that many, at most 2.
2. **Host arguments.** From the same dummy host, record `"$@"`. Expected: Chrome passes `chrome-extension://<id>/`;
   Firefox passes the manifest path and the extension id.
3. **Signing identities.** Run `codesign -dr - "/Applications/Google Chrome.app"` (and Firefox, Brave, Edge, Chromium if
   installed) and record identifier and team id. Expected, to be confirmed: Chrome `com.google.Chrome` / `EQHXZ8M8AV`,
   Firefox `org.mozilla.firefox` / `43AQ936H96`, Brave `com.brave.Browser` / `KL8N8XSYF4`, Edge `com.microsoft.edgemac` /
   `UBF8T346G9`.
4. **Service worker lifetime.** In Chrome, confirm that an open `runtime.connectNative` port keeps the MV3 service worker
   alive for 10 minutes of idle.
5. **Firefox MV3.** Confirm from MDN: `background.scripts` with `"type": "module"`, how host permissions are granted at
   install, and the minimum version to put in `strict_min_version`. Confirm a non-extractable `CryptoKey` can be stored
   in IndexedDB from the background context in both browsers.
6. **Non-activating window.** Check whether a Slint window can be shown without activating the app (the app already
   reaches `NSWindow` in `app/src/os/appkit.rs`; try `orderFrontRegardless` without `activate`). Needed for the save
   prompt (section 8.4). Fallback if not: show it normally and give focus back on close with `give_focus_back`.
7. **`psl` crate.** Confirm the current version, that it embeds the list at build time (no network), and that it includes
   the private section (`github.io` must be a suffix).

## 6. Phase 1 — URI matching in `vk-vault`

All matching runs in the daemon. New file `crates/vault/src/uri_match.rs`, pure functions, no I/O.

Dependencies to add in the workspace `Cargo.toml` and `crates/vault/Cargo.toml`: `psl` (VERIFY version) and `regex`
(already in `Cargo.lock` transitively; use that version).

```rust
pub enum MatchRule { Domain, Host, StartsWith, Exact, Regex, Never }   // Bitwarden 0..=5
pub enum DefaultMatch { Domain, Host }

pub struct PageUrl { /* origin: url::Url, path: String */ }
impl PageUrl { pub fn new(origin: &str, path: &str) -> Option<Self>; pub fn host_ascii(&self) -> &str; pub fn is_https(&self) -> bool; }

/// `rule` is the stored `match` value; `None` uses `default`.
pub fn matches(saved_uri: &str, rule: Option<u8>, default: DefaultMatch, page: &PageUrl) -> bool;
```

Rules (page URL = `origin + path`; query and fragment are never sent and are stripped from the saved URI before
comparing):

| Rule | Matches when |
|---|---|
| Domain (0) | Registrable domains are equal (`psl::domain_str`). Decide the host kind with `url::Url::host()` **before** calling psl: an IPv4/IPv6 address, `localhost`, or a name whose public suffix is not on the list (`psl::suffix(host).is_known() == false`, e.g. `.local`, `.internal`) is compared by full host instead. Phase 0 measured that psl alone is not enough: `psl::domain_str("192.168.1.2")` returns `1.2` and `nas.local` returns itself. A trailing dot on a host is dropped first. Port ignored. |
| Host (1) | Host and port are equal (default port when absent). |
| StartsWith (2) | The page URL starts with the saved URI (both lowercased in scheme and host only). |
| Exact (3) | The page URL equals the saved URI. A saved URI with no path equals path `/`. |
| Regex (4) | `regex::RegexBuilder::new(saved).case_insensitive(true).size_limit(1 << 20).build()` matches the page URL. A pattern that fails to build never matches. |
| Never (5) | Never. |
| unknown value | Never. |

Common to all rules:

- A saved URI without `://` is parsed as `https://` + the text. If it still does not parse, it never matches.
- A saved URI whose scheme is not `http` or `https` never matches.
- **Scheme downgrade:** an `http` page matches only a saved URI that is itself `http`. An `https` page matches both.
- Hosts are compared in ASCII form as `url::Url` gives them (lowercase, punycode).

Unit tests in the same file. Expected values come from this table, not from running the code:

| saved | rule | page | match |
|---|---|---|---|
| `https://github.com/login` | default Domain | `https://gist.github.com/x` | yes |
| `https://github.com` | default Domain | `https://github.com.evil.io/` | no |
| `https://alice.github.io` | Domain | `https://bob.github.io/` | no |
| `github.com` | default Domain | `https://github.com/` | yes |
| `https://example.com` | Domain | `http://example.com/` | no |
| `http://nas.local:5000` | Domain | `http://nas.local:5001/` | yes |
| `http://192.168.1.2` | Domain | `http://192.168.1.3/` | no |
| `https://a.corp.internal` | Domain | `https://b.corp.internal/` | no |
| `http://localhost:3000` | Domain | `http://localhost:4000/` | yes |
| `https://example.com.` | Domain | `https://example.com/` | yes |
| `https://a.example.com:8443` | Host | `https://a.example.com/` | no |
| `https://a.example.com` | Host | `https://b.example.com/` | no |
| `https://example.com/app` | StartsWith | `https://example.com/app/login` | yes |
| `https://example.com/app` | StartsWith | `https://example.com/other` | no |
| `https://example.com/login?x=1` | Exact | `https://example.com/login` | yes |
| `https://example.com` | Exact | `https://example.com/` | yes |
| `^https://[a-z]+\.example\.com/` | Regex | `https://dev.example.com/` | yes |
| `(` | Regex | anything | no |
| `https://example.com` | Never | `https://example.com/` | no |
| `androidapp://com.x` | default | `https://x.com/` | no |
| `https://xn--e1afmkfd.xn--p1ai` | Domain | `https://пример.рф/` (sent by the browser as punycode) | yes |

Index changes in `crates/vault/src/index.rs`:

- `list_fields` currently collects `uris: Vec<Zeroizing<String>>` and skips empty ones. Change the element to
  `(Zeroizing<String>, Option<u8>)` so each decrypted URI keeps the `match` value of its own `LoginUri`.
- Add to `Entry` a field `match_uris: Box<[(Zeroizing<String>, Option<u8>)]>` (original case, not lowercased). It is
  dropped and wiped with the entry on lock; `Zeroizing` does the wiping.
- Keep `hay` and `primary_uri` exactly as they are.

New file `crates/vault/src/vault/browser.rs` with inherent methods on `Vault` (not on the `VaultService` trait, so
`MockVault` and `RemoteVault` do not change). Find how `search` reads the index in `vault/service_impl.rs` and read it the
same way.

```rust
pub struct LoginMatch { pub summary: ItemSummary, pub matched_uri: Arc<str> }

impl Vault {
    /// Non-deleted login items with at least one URI matching `page`. Favourites first, then by name.
    /// `Err(Error::Locked)` when locked.
    pub fn logins_for(&self, page: &PageUrl, default: DefaultMatch) -> Result<Vec<LoginMatch>>;
    /// Whether item `id` matches `page` (for validating the UI's answer).
    pub fn login_matches(&self, id: &ItemId, page: &PageUrl, default: DefaultMatch) -> Result<bool>;
}
```

Tests: next to the existing index tests, using `testutil.rs` fixtures: two logins on the same domain, one deleted login
(excluded), one card (excluded), locked vault → `Locked`.

Phase 1 validation: `cargo test -p vk-vault` passed (80 unit tests, 32 integration tests); final regex-policy regression brings the unit total to 81. `cargo clippy -p vk-vault --all-targets --all-features` passes.

## 7. Phase 2 and 3 — socket, host mode

### 7.1 `vk-ipc`: new module `crates/ipc/src/browser/`

`pub mod browser` in `lib.rs`. It reuses the private `peer` and `frame` modules, which is why it lives in this crate.

- `protocol.rs` — serde types for section 3: `HostHello`, `Caller`, `ParentInfo`, `KnownBrowser`, `HostWelcome`,
  `Request` (`#[serde(tag = "type", rename_all = "snake_case")]`), `Response`, `ErrorCode`, `Event`. Fields that hold a
  password are `Zeroizing<String>`. Add `#[serde(deny_unknown_fields)]` to nothing: unknown fields are ignored, an unknown
  `type` is `unknown_type`.
- `server.rs` — the listener.
- `host.rs` — the relay used by host mode.

```rust
pub struct BrowserConnection {
    pub id: u64,                                   // unique per daemon run
    pub hello: HostHello,
    pub incoming: mpsc::Receiver<Zeroizing<Vec<u8>>>,   // raw JSON bodies; closed = host gone
    pub outgoing: mpsc::Sender<Zeroizing<Vec<u8>>>,     // capacity 16
}

pub struct BrowserServeOptions { pub verifier: Arc<dyn PeerVerifier>, pub require_verified_parent: bool, pub max_connections: usize }

/// Binds `path` like `serve_with` does (0600 socket in a 0700 directory, stale socket replaced).
pub async fn serve_browser(path: PathBuf, options: BrowserServeOptions,
                           connections: mpsc::Sender<BrowserConnection>) -> Result<BrowserServerHandle, IpcError>;
```

Per accepted socket, in this order: `peer::credentials` → uid equals ours → `verifier.verify` → read `HostHello` within
5 s → `protocol == 1` else `HostRefused version` → `parent.browser.is_some()` or not `require_verified_parent`, else
`HostRefused unverified_parent` → a free slot, else `HostRefused busy` → `HostWelcome` → hand a `BrowserConnection` to
`connections` → pump frames both ways until either side closes. Move the directory, stale-socket and bind helpers of
`server/mod.rs` to `pub(crate)` and call them; do not copy them.

Dropping `BrowserServerHandle` aborts everything and removes the socket file, as `ServerHandle` does.

Tests in `crates/ipc/tests/browser.rs` (same style as `tests/server.rs`, with an accept-all verifier): hello/welcome round
trip; wrong protocol refused; unverified parent refused when required; fifth connection `busy`; a 64 KiB + 1 frame closes
the connection; closing the client closes `incoming`.

### 7.2 Host mode detection: `app/src/cli.rs`, `app/src/main.rs`

Browsers pass arguments that `cli::parse` rejects, so detect host mode **before** `cli::parse`:

```rust
pub enum HostCaller { Chromium { origin: String }, Firefox { extension_id: String } }
/// `Some` when the arguments are exactly what a browser passes to a native messaging host.
pub fn browser_host_caller(args: &[String]) -> Option<HostCaller>;
```

- Chromium: the first argument starts with `chrome-extension://` and the rest of it is 32 characters `a`–`p`, with or
  without a trailing `/` (Chrome's docs show it without one, `allowed_origins` requires one); normalise to the slash
  form. Extra arguments are ignored. The real value is recorded in section 14.
- Firefox: exactly two arguments, the first ends with `/org.vaultkeeper.browser.json`, the second is the extension id
  constant.
- Adjust to what spike 0.2 recorded.

In `main`: after `harden_process()`, collect the arguments, call `browser_host_caller`; if `Some`, call
`init_logging_stderr("browser-host")` and `vaultkeeper::browser_host::run(caller)`, then return.

**Logging:** `tracing_subscriber::fmt::layer()` writes to stdout by default. In host mode build the layer with
`.with_writer(std::io::stderr)`. While there, check what the existing `init_logging` does and make the daemon and UI
layers write to stderr too, as its doc comment already claims.

### 7.3 Host: `app/src/browser_host/` (`mod.rs`, `parent.rs`, `native.rs`)

`run(caller)`:

1. Build a current-thread Tokio runtime. Do not initialise Slint, the tray or the vault.
2. `parent::identify()` → `ParentInfo`.
3. Connect to `data_dir/browser.sock`. If it fails with `NotFound` or `ConnectionRefused`: start the app, then retry every
   200 ms for 5 s. Start it with `/usr/bin/open -g -a <bundle path> --args --tray` when `current_exe` is inside a
   `*.app/Contents/MacOS/` directory, otherwise spawn `current_exe --tray` detached. If still not connected, write one
   native message `{"event":"unavailable","reason":"not_running"}` and exit 0.
4. Send `HostHello`, read the answer. On `HostRefused`, write `{"event":"unavailable","reason":"<reason>"}` and exit 0.
5. Relay until either side closes: stdin native messages → socket frames; socket frames → stdout native messages. Buffers
   are `Zeroizing<Vec<u8>>`. Enforce the 64 KiB limits. Exit 0 on EOF from the browser.

`native.rs`: `read_message(stdin)` and `write_message(stdout)` with native-endian `u32` lengths. Unit-test them with
in-memory pipes, including a length over the limit and a truncated body.

`parent.rs` (macOS):

1. `ppid = getppid()`. If `ppid <= 1`, the browser is `None`.
2. Get the parent's code object with `SecCodeCopyGuestWithAttributes` and the **pid** attribute. `peer.rs` already has the
   same call with the audit-token attribute in `mod code_identity`; add a pid variant there and export a function
   `pub fn check_pid(pid: i32, requirement: &str) -> io::Result<()>` from `vk_ipc`.
3. Try each known browser's requirement string, first match wins:
   `identifier "<bundle id>" and anchor apple generic and certificate leaf[subject.OU] = "<team id>"`, with the pairs
   recorded by spike 0.3.
4. Call `getppid()` again; if it changed, the browser is `None`.
5. The caller kind must fit the browser: a `Firefox` caller with a Chromium-family parent (or the reverse) → `None`.

`KnownBrowser` has a display name used in prompts. **Version 1 knows only "Google Chrome" and "Firefox"**: Phase 0 verified
those two signatures on this machine (section 14). Brave, Edge and Chromium were not installed, so their identifiers
stay unverified; add each one only after reading its real signature with `codesign -dr -`. Note that Chrome's own
designated requirement also admits the Beta, Dev and Canary identifiers; ours names only `com.google.Chrome`.

Debug builds only (`cfg(debug_assertions)`): the environment variable `VAULTKEEPER_DEV_BROWSER=1` on the **daemon** sets
`require_verified_parent: false`, so an unsigned Chromium works during development. Release builds ignore it.

Done when: `cargo test -p vk-ipc --test browser` and `cargo test -p vaultkeeper browser_host cli` pass, and a manual check
shows `printf` of a framed `{"type":"status","id":1}` into the binary started from a terminal answers
`unavailable/unverified_parent`.

## 8. Phase 4 and 5 — daemon logic and native UI

### 8.1 Settings (`app/src/settings.rs`, with `#[serde(default)]` they need no migration)

| Field | Default | Meaning |
|---|---|---|
| `browser_integration: bool` | `false` | Master switch. Off: `browser.sock` is not bound, manifests are removed. |
| `browser_touch_id: bool` | `false` | Every release that shows the picker also needs Touch ID, asked by the daemon. |
| `browser_save_prompts: bool` | `true` | Offer to save and update. |
| `browser_copy_totp: bool` | `true` | After a fill, copy the item's current TOTP code. |
| `browser_default_match: BrowserMatch` | `Domain` | `Domain` or `Host`, for URIs without their own rule. |

Add them to `Default`, to the Settings window (section 8.5) and to `apply_settings` in `daemon/core.rs`: when
`browser_integration` flips, start or stop the listener and install or remove manifests.

### 8.2 UI socket protocol: `crates/ipc/src/protocol.rs`

Bump `PROTOCOL_VERSION` to 10. Append (never insert before existing variants):

```rust
// Event
BrowserPrompt { seq: u64, request_id: u64, prompt: BrowserPrompt },
// UiMessage
BrowserPromptReply { request_id: u64, reply: BrowserReply },

pub enum BrowserPrompt {
    Pair { browser: String, fingerprint: String },
    Fill { browser: String, host: String, insecure: bool, matches: Vec<ItemSummaryDto>,
           touch_id: bool, return_to: Option<TypingTarget> },
    Save { browser: String, host: String, username: String, update_of: Option<ItemSummaryDto>,
           choices: Vec<ItemSummaryDto>, return_to: Option<TypingTarget> },
}
pub enum BrowserReply {
    Dismissed,
    PairApproved,
    Fill { item_id: Arc<str>, confirmed_other_site: bool },
    Save { target: Option<Arc<str>> },   // None = create a new item
    NeverForSite,
}
```

Mirror the SSH plumbing exactly: `DaemonEvent::BrowserPrompt { seq, prompt, reply: oneshot::Sender<BrowserReply> }` in
`server/mod.rs`; registration and resolution by `request_id` in `server/connection.rs` next to `Approvals`; a withdrawn
prompt becomes `Event::Skipped`; `UiEvent::BrowserPrompt` in `client/events.rs`; `Bridged::Command(UiCommand::
ShowBrowserPrompt(..))` in `app/src/ui_process/bridge.rs`. A dropped sender or a disconnected UI counts as `Dismissed`.
Extend the round-trip tests in `crates/ipc/tests/roundtrip.rs` and the position test in `protocol.rs`.

### 8.3 Daemon: `app/src/daemon/browser/`

- `mod.rs` — `BrowserControl`, owned by `Daemon` like `SshControl`: the listener handle, live sessions, the pairing store.
- `session.rs` — one task per `BrowserConnection`: parse, validate, rate-limit, answer.
- `pairing.rs` — `browsers.json` store.
- `fill.rs`, `save.rs` — the two flows.
- `manifests.rs` — section 9.

Add `BROWSER_SOCKET: &str = "browser.sock"` and `BROWSERS_FILE: &str = "browsers.json"` to `app/src/os/layout.rs`.

**Start condition.** Bind the socket only when `browser_integration` is on **and** the running binary is signed with the
hardened runtime (read the flags with `SecCodeCopySigningInformation`; add `pub fn has_hardened_runtime() -> bool` beside
the code-identity helpers). Without the hardened runtime another process could inject code into the host. Exceptions:
`vw-it` builds, and debug builds with `VAULTKEEPER_DEV_BROWSER=1`. When refused, log a warning and show the reason in
Settings.

**Session state** (in memory, per connection): `caller`, `browser`, `paired_key: Option<[u8; 65]>`, `challenge`,
`remembered: HashMap<String /*origin*/, ItemId>`, the token buckets, `fill_in_flight: bool`.

**Pairing store** `browsers.json` (0600, atomic write like `settings_file.rs`):

```json
{ "paired": [ { "public_key": "<base64>", "browser": "chrome", "caller": "chrome-extension://…/", "added": 1731200000 } ],
  "never_save_salt": "<base64 16 bytes>", "never_save": [ "<hex sha256(salt ‖ registrable domain)>" ] }
```

**`hello` / `prove`.** `hello`: decode the key (must be 65 bytes starting `0x04` and a valid point), create a 32-byte
challenge with `rand`, answer. `prove`: verify with `p256::ecdsa::VerifyingKey::from_sec1_bytes` and
`Signature::from_slice` (enable the `ecdsa` feature of `p256` in the workspace manifest). Bad signature → `denied` and
close. Known key and same `caller` → paired. Unknown key → send `BrowserPrompt::Pair`, wait at most 60 s; `PairApproved`
→ store and paired; anything else → `denied`, and further `hello` on this connection is `denied` too.

**`fill`** (`fill.rs`), in order:

1. Validate. `PageUrl::new`. An `http` page whose host is not `localhost`, a loopback or private-range IP, or a
   single-label/`.local` name → `insecure_page`.
2. State: `LoggedOut` → `logged_out`. `Locked` → continue; the UI shows the lock screen first (step 5).
3. If unlocked, not `choose`, and `remembered[origin]` exists, the item still matches and is not a re-prompt item →
   go to step 8 with it. No prompt.
4. `return_to = typing_target_off_main()` (the browser gets focus back afterwards).
5. If locked: send `UiCommand::UnlockInTray` and wait for `Unlocked` the way `wait_unlocked` does, at most 120 s, ending
   early when the connection closes → `locked` on timeout.
6. `matches = vault.logins_for(page, default)`. Send `BrowserPrompt::Fill` (an empty `matches` is fine: the picker opens
   in search mode). Wait for the reply, at most 90 s, also ending when the connection closes.
7. Reply `Dismissed` → `cancelled`. Reply `Fill { item_id, confirmed_other_site }`: if
   `!vault.login_matches(item_id, page)` and `!confirmed_other_site` → `denied`. If `browser_touch_id` → the daemon asks
   Touch ID itself; generalise `confirm_presence` to take the reason text ("fill a login in Google Chrome") and a
   "requester gone" future. Refused → `denied`.
8. Re-check `Unlocked`. `vault.reveal(id, CopyField::Username)` and `Password`; a missing field becomes `null`. Remember
   `origin → id` for this connection, unless the item is a re-prompt item. `note_activity()`. If `browser_copy_totp` and
   the item has TOTP: copy the current code through the daemon's `ClipboardKeeper` with the normal auto-clear.
9. Answer. Append one line to the browser activity log (section 10): time, browser, host, item id, "picker" or
   "remembered". Never a secret.

Clear every session's `remembered` in `on_state` where `left_session` is true and where the vault locks (beside
`ssh.forget_approvals()`), and on `PowerEvent::WillSleep` / `ScreenLocked` regardless of `lock_on_sleep`.

**`save_candidate`** (`save.rs`): answer `{}` first, then continue in a spawned task that owns the candidate
(`Zeroizing`).

1. Stop if `browser_save_prompts` is off, the state is `LoggedOut`, the page is insecure (same rule as fill), or the
   registrable domain is in `never_save`.
2. Locked: keep at most 3 candidates for at most 10 minutes; evaluate them after the next unlock; wipe them on logout,
   account switch and quit. Do not open the lock screen for a save.
3. Dedupe: keep `HMAC-SHA256(random per-run key, origin ‖ 0 ‖ username ‖ 0 ‖ password)` of every candidate handled in
   the last 10 minutes; a repeat stops here.
4. `matches = logins_for(page)`. Compare usernames with the item subtitle, case-insensitively.
   - A match with the same username: `reveal` its password and compare in constant time (`subtle`, already in the
     tree). Equal → stop. Different → prompt `Save { update_of: Some(item) }`.
   - `username` empty and `kind == "change"`: one match → `update_of: Some(it)`; several → `choices = matches`;
     none → stop.
   - No match with that username and `username` not empty → prompt `Save { update_of: None }`.
   - A matching item with `editable == false` is not offered as an update target.
5. Reply `Save { target: Some(id) }` → `vault.draft(id)`, replace the password, `vault.save(Some(id), draft)`.
   `Save { target: None }` → a new `ItemDraft` with `ItemData::Login { username, password, totp: empty, uris: [origin] }`,
   `name` = host without a leading `www.`, no folder. `NeverForSite` → add the hash. `Dismissed` → nothing.
6. A failed write (`Offline`, `Conflict`, …): add a new `UiCommand::Toast { text, error: true }` (in `vk-ipc` and in
   `app/src/app/commands.rs`, shown with the existing `App::toast`) and send "Could not save the login: <reason>".

### 8.4 Native windows: `app/ui/browser.slint`, `app/src/app/browser.rs`

Export the three components from `app/ui/app.slint`. Build them only from `Theme` tokens and `kit.slint` widgets, copying
the frame of `SshPrompt` in `app/ui/ssh.slint`: `no-frame`, `always-on-top`, `background: Theme.surface`, 1 px
`Theme.border`, `Theme.radius-popup`, padding 18 px, title in `Theme.font-title` weight 600 with a 20 px `Icon` tinted
`Theme.accent`, buttons right-aligned with `Btn` (`BtnKind.primary` for the default action), Esc and Return handled in a
`FocusScope`, the 3 px countdown bar. No hard-coded colours. Call `self.apply_theme(&window)` on each, and add each to
`apply_theme_everywhere` so a theme change while it is open applies.

`app/src/app/browser.rs` mirrors `app/src/app/ssh.rs`: a queue with ids, one prompt on screen at a time, a Rust
`Timer` for the timeout, late events for an old id ignored, `deny_all_browser()` called wherever `deny_all_ssh()` is
called, and the lock-screen-first path for a prompt that arrives while locked. After the answer, if no other prompt is
open, `hooks.autotype.give_focus_back(return_to)`.

**`BrowserPicker`** (480 × 360, placed like the Quick Panel):

- Header: "Fill login", then `"<browser> · <host>"` in `Theme.text-muted`. If `insecure`: a `warning.svg` icon and "Not
  encrypted (http)" in `Theme.warn-text`.
- A search `Field`, focused. Empty query: the list shows `matches`. Typed query: the list shows
  `vault.search(query, Filter { kind: Some(ItemKind::Login), .. })`, with items that are not in `matches` marked by a
  muted "other site" label.
- Rows reuse the look of `ItemRow` without copy buttons: kind chip, name, username. Row height `Theme.row-height`.
- Empty state (no matches, no query): `EmptyState` "No login saved for <host>" and the hint "Type to search the vault".
- Keys: ↑/↓ move, Return picks, Esc dismisses. 60 s timeout dismisses.
- Picking an "other site" item replaces the list with a confirmation: "<item name> is saved for <its primary host>, not
  <host>. Fill it here anyway?" with buttons "Cancel" (default, Return) and "Fill anyway". Only "Fill anyway" sends
  `confirmed_other_site: true`.
- Picking a re-prompt item shows an inline master-password `Field`; submit calls `vault.verify_master_password`; only
  success sends the reply.
- When `touch_id` is set, the primary hint reads "Return · then Touch ID".

**`BrowserPairPrompt`** (420 × 260): "Connect <browser>?", the text "The Vaultkeeper extension in <browser> wants to
connect. Check that this code matches the one in the extension:", the fingerprint in `Theme.mono` at `Theme.font-totp`,
buttons "Deny" (Esc, default) and "Connect". 60 s timeout denies. Return does **not** approve here.

**`BrowserSavePrompt`** (380 × 220, top-right corner of the screen with the cursor, shown without taking focus from the
browser, see "Not taking focus" below): "Save login?" or "Update password?", `"<browser> · <host>"`, the username in `Theme.mono`
(truncated to 64 characters), for `choices` a `Select` of items. Buttons: "Never for this site", "Not now" (Esc), "Save" /
"Update" (primary). 30 s timeout = "Not now". The password is not shown and never crosses `ui.sock`.

**Not taking focus (Phase 0, spike 6, Slint 1.18.1 on this Mac; PARTLY VERIFIED, see the open test below).** Two runs
of the same scenario (Chrome frontmost, the spike hands focus back to Chrome and confirms it, then shows a `no-frame`,
`always-on-top` Slint window with `show()` and no other activation call):

- Backend set up like the daemon (`ActivationPolicy::Accessory`, `with_activate_ignoring_other_apps(false)`): Chrome
  stays frontmost, the app stays inactive, the window is visible at level 3, not occluded, not the key window.
- Default backend (activates at launch): `show()` made the app frontmost and the window key. So `show()` **does**
  activate a process that activated at launch, even after it handed focus back.

The real UI process is `Accessory` plus `with_activate_ignoring_other_apps(true)` (`Backend::Ui`), which is the second
case, not the first. So until the open test below is done, assume a UI process that has activated at least once steals
focus when it shows the save prompt. The `show` helper at `app/src/app/mod.rs:557` is a plain `component.show()` and
does nothing extra. Activation comes from two places in this code base; the save prompt must avoid both, and that alone
may not be enough:

1. `Backend::Ui` in `app/src/run.rs` sets `with_activate_ignoring_other_apps(true)`. Make it a field,
   `Backend::Ui { on_input, activate_at_launch }`, and start the UI process with a new flag `--no-activate` (add to
   `cli.rs` and `Launcher`, next to `--first-unlock`) when the command that caused the start is a save prompt. This does
   not help a UI process that is already running and has activated before (it lingers 120 s after its last window).
2. `App::handle` in `app/src/app/commands.rs` calls `self.hooks.dock.activate()` for every command where
   `UiCommand::shows_a_window()` is true, and that function is a deny-list (everything except `VaultChanged`,
   `ReloadSettings`, `OfflineChanged`, `SyncFinished`). A new `ShowBrowserPrompt` variant would therefore activate by
   default. Add the Save kind to the exclusions; `Fill` and `Pair` stay as they are (the user asked for them, and they
   need the keyboard). Add a test next to the existing command tests that a Save prompt does not call
   `hooks.dock.activate()`.

**Result of the test (2026-11-10, screen unlocked, Ghostty in front): in all five variants (a, b and c, alone or with
`--yield-after`) the other app stayed frontmost, our app was inactive, and the window was visible at level 3, not the
key window.** So once an Accessory process has handed focus back, a later plain `show()` does not steal it, even if the
process activated at launch (a) or later (b). This contradicts the earlier default-backend observation; that run was
confounded (it did not hand focus back first), so do not rely on it. **Limits of the result:** the spike always hands
focus back before `show()`, and the real UI process does not do that on its own. A freshly started UI process still
activates at launch (`Backend::Ui`), so item 1 below stays needed, and item 2 stays as cheap insurance. Verify the real
app in Phase 5 with a manual check (browser in front, trigger a save prompt, confirm the browser stays frontmost); if it
fails, apply the (c) fallback below. The test as run, for reference: `experiments/focus-spike` has the flags:
`--launch-activate` (a), `--pre-activate` (b), each alone and with `--yield-after` (c). Run
`experiments/focus-spike/run-variants.sh` (one process per variant; it refuses to run on a locked screen) and read the
`[1.5s after show]` line of each.

| Variant | What it models | Stealing focus means |
|---|---|---|
| (a) `--launch-activate` | the real UI process: Accessory, activates at launch, later shows a window | the line says `frontmost = focus-spike` |
| (b) `--pre-activate` | a `--no-activate` UI that later activated for a Fill or the Manager, then shows a window | same |
| (c) either, plus `--yield-after` | `show()` followed at once by `give_focus_back` | ends with the other app frontmost and `visible=true` for the window = acceptable fallback |

Decision: if (a) and (b) leave the other app frontmost, items 1 and 2 above are enough. If they do not, but (c) works,
call `hooks.autotype.give_focus_back(return_to)` right after showing the save prompt (expect a brief flicker of the
browser's title bar). If (c) also fails, get the window's `NSWindow` through `with_winit_window` and order it front
with `orderFrontRegardless` instead of `show()`, and test that. Until then, Phases 1 to 3 do not depend on this.

Consequence: until the user clicks the save prompt it is not the key window, so Esc and Return do nothing. The prompt
is therefore mouse-first; show the hint "Click to answer" in `Theme.text-muted` and rely on the 30 s timeout. Still to
check by hand in Phase 5: whether the first click both activates the app and presses the button (winit should accept
the first mouse click) and whether focus returns to the browser afterwards through `give_focus_back`.

Mock support: add `--demo-browser-fill`, `--demo-browser-pair`, `--demo-browser-save` to `cli.rs`, handled like
`--demo-ssh` in `main.rs`, so each window can be opened on the mock vault in both themes.

Tests in `app/tests/browser_prompts.rs` with the Slint testing backend, following `app/tests/ssh_and_commands.rs`:
picker returns the picked id; Esc dismisses; other-site pick needs the second confirmation; timeout dismisses; a prompt
arriving while locked waits behind the lock screen and is dismissed when the lock screen is closed; lock closes an open
prompt; pair prompt does not approve on Return.

Daemon tests in `app/tests/browser_daemon.rs` following `app/tests/daemon_ipc.rs` (the test process plays both the UI and
the host, `Peers::AnyOfThisUser`, parent check off): unpaired request refused; pairing with a real P-256 key made in the
test; bad signature refused; fill released only for the approved item; `login_matches` false without
`confirmed_other_site` → `denied`; remembered fill needs no prompt on the same connection and does need one on a new
connection; lock clears remembered; rate limit; `save_candidate` with an equal password produces no prompt; with a
different one produces `Save { update_of }` and the vault item changes after `Save`.

### 8.5 Settings window (`app/ui/settings.slint`, `app/src/app/settings_ctl.rs`)

A new section `SectionLabel { text: "BROWSERS"; }` after "SSH AGENT", built from `SettingRow`, `Toggle`, `Segmented`:

- "Browser integration" toggle, with one muted line under it for the state: "Off", "On", or the reason it cannot start.
- One row per installed browser (detected by its application-support directory, section 9) with a toggle "Install for
  <browser>".
- "Require Touch ID to fill" (shown only when Touch ID is available), "Offer to save logins", "Copy TOTP code after
  filling", "Match sites by" (`Segmented`: "Domain", "Exact host").
- "Paired browsers": one row per entry with browser name, fingerprint in `Theme.mono` and a "Remove" `Btn`. Removing
  rewrites `browsers.json` and closes that key's live connections.

## 9. Phase 6 — native messaging manifests (`app/src/daemon/browser/manifests.rs`)

Host name: `org.vaultkeeper.browser`. File name: `org.vaultkeeper.browser.json`. Directories under
`~/Library/Application Support/`:

| Browser | Directory |
|---|---|
| Chrome | `Google/Chrome/NativeMessagingHosts/` |
| Chromium | `Chromium/NativeMessagingHosts/` |
| Brave | `BraveSoftware/Brave-Browser/NativeMessagingHosts/` |
| Edge | `Microsoft Edge/NativeMessagingHosts/` |
| Firefox | `Mozilla/NativeMessagingHosts/` |

```json
{ "name": "org.vaultkeeper.browser", "description": "Vaultkeeper", "type": "stdio",
  "path": "/Applications/Vaultkeeper.app/Contents/MacOS/vaultkeeper",
  "allowed_origins": ["chrome-extension://<CHROME_EXTENSION_ID>/"] }
```

Firefox uses `"allowed_extensions": ["browser-extension@vaultkeeper"]` instead of `allowed_origins`.

- `path` is `std::env::current_exe()` canonicalized. Write atomically, mode 0644, only when the browser's parent
  directory already exists (do not create `Google/Chrome` for a browser that is not installed).
- `CHROME_EXTENSION_ID` and the Firefox id are constants in one Rust file and one extension file; a unit test in
  `browsers/` reads the Rust file and asserts they are equal.
- On daemon start and on every accepted browser connection: for each enabled browser, read the manifest and compare it
  byte for byte with what would be written. Different → rewrite it, log a warning and queue
  `UiCommand::Toast { text: "The browser connection file for <browser> was changed and has been restored", error: true }`.
- Turning a browser off, or integration off, deletes its manifest.

Tests: unit tests against a temp directory for write, compare, restore and delete.

## 10. Phase 7 to 9 — the extension (`./browsers`)

### 10.1 Layout and tooling

```
browsers/
  package.json  pnpm-lock.yaml  tsconfig.json  vite.config.ts
  scripts/build.mjs          Vite+ → dist/chrome, dist/firefox
  scripts/gen-theme.mjs      app/ui/theme.slint → src/ui/theme.css
  manifest.base.json  manifest.chrome.json  manifest.firefox.json
  src/shared/      protocol.ts (types of section 3.3), ids.ts, origin.ts
  src/background/  index.ts, native.ts (port, ids, reconnect), pairing.ts (key, sign), router.ts
  src/content/     index.ts, detect.ts, fill.ts, icon.ts, capture.ts
  src/ui/          popup.html popup.ts popup.css theme.css icons/
  test/            *.test.ts (Vite+ `vp test` + jsdom)
  README.md        build, load unpacked, sign
```

TypeScript 7, strict, with `typescript@^7` for the compiler. No runtime dependencies. Use Vite+ (`vite-plus`) for
builds, tests, formatting and linting instead of standalone esbuild, Vitest or Biome; add `jsdom` and `web-ext` as needed.
Vite+ uses Vitest internally for `vp test`, and Oxlint/Oxfmt for `vp check`. Use pnpm for dependency management; verify the
installed Vite+ and TypeScript 7 versions and compatibility before use. Add `browsers/node_modules` and `browsers/dist` to
`.gitignore`. Before writing manifests,
read the current Chrome and MDN docs for MV3 manifests and native messaging.

Manifest (merged by `build.mjs`): `manifest_version: 3`; permissions `nativeMessaging`, `contextMenus`; host permissions
`https://*/*`, `http://*/*`; one content script for those matches with `all_frames: true`, `run_at: "document_idle"`;
`action.default_popup`; `commands.fill` with suggested key `Ctrl+Shift+L` / mac `Command+Shift+L`; no
`web_accessible_resources`; no `externally_connectable`. Chrome: `background.service_worker` with `type: "module"` and the
`key` field (the public key that fixes the extension id). Firefox: `background.scripts` with `type: "module"` and
`browser_specific_settings.gecko.id = "browser-extension@vaultkeeper"` plus the `strict_min_version` from spike 0.5.

Use the `chrome.*` promise API in shared code; it exists in both browsers under MV3 (**VERIFY** for Firefox; otherwise
`const api = globalThis.browser ?? globalThis.chrome`).

Loading during development (verified in Phase 0): branded Chrome ignores `--load-extension` ("not allowed in Google
Chrome, ignoring"), even with `--disable-features=DisableLoadExtensionCommandLineSwitch`. A developer loads
`dist/chrome` by hand through `chrome://extensions` → Developer mode → Load unpacked. Firefox can be driven with
`web-ext run --source-dir dist/firefox --firefox /Applications/Firefox.app/Contents/MacOS/firefox`. Automated end-to-end
runs of the Chrome side need Chrome for Testing or Chromium, whose native-messaging directory is separate (Chrome's docs:
the `NativeMessagingHosts/` subdirectory of the user profile directory; whether `--user-data-dir=X` moves it to
`X/NativeMessagingHosts/` is checked in section 14).

### 10.2 Theme (`scripts/gen-theme.mjs`)

Parse every line of `app/ui/theme.slint` of the form `out property <color> NAME: dark ? #AAAAAA : #BBBBBB;` and emit
`src/ui/theme.css`:

```css
:root { --bg: #F6F7F9; --surface: #FFFFFF; /* … light values … */ }
:root[data-theme="dark"] { --bg: #141518; /* … */ }
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) { /* dark values again */ } }
```

Write the derived tokens by hand below the generated block: `--hover`, `--selection`, `--border-subtle` with the same
alpha values as the Slint file; sizes `--font-body: 13px`, `--font-meta: 11px`, `--font-title: 17px`,
`--control-height: 28px`, `--radius-control: 6px`, `--radius-popup: 10px`, `--gap: 8px`, `--padding: 12px`; font
`-apple-system, system-ui, sans-serif`, mono `Menlo, monospace`.

The generated file is committed. A `vp test` test runs the generator in memory and fails when the committed file differs, so
a colour change in the app cannot be forgotten.

`data-theme` comes from the app: `"light"`, `"dark"`, or absent for `"system"`. The popup sets it from the `theme` of
`prove`/`status`/the `state` event. The in-page icon and toast get it the same way (the background forwards the theme to
content scripts with each fill result and on request).

### 10.3 Background

- `native.ts`: `connect()` opens `runtime.connectNative("org.vaultkeeper.browser")` lazily — only for a user action (icon
  click, shortcut, context menu, popup opened) or a save candidate. Never at browser start. `request(type, fields)`
  returns a promise, matches responses by `id`, times out at 130 s. On disconnect: reject pending requests, drop the port,
  reconnect on the next action. Phase 0 could only test Firefox's idle behaviour under web-ext (section 14): in this
  phase, re-test with a normally installed add-on that an idle port survives 10 minutes; if it does not, make the host
  send `{"event":"ping"}` every 20 s while connected, and have the background ignore it. An `unavailable` event is shown in the popup with its reason.
- `pairing.ts`: on first use `crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign"])`; store
  the `CryptoKeyPair` in IndexedDB (database `vaultkeeper`, store `keys`, key `"pairing"`). `exportKey("raw", publicKey)`
  → base64 for `hello`. Sign the bytes of section 3.3 with `{ name: "ECDSA", hash: "SHA-256" }` for `prove`. Compute the
  fingerprint for the popup.
- `router.ts`: handles `runtime.onMessage`. For every message: require `sender.id === runtime.id` and `sender.tab`;
  compute `frameOrigin = new URL(sender.url).origin` and `tabOrigin = new URL(sender.tab.url).origin`; require the scheme
  to be `http:` or `https:` and `frameOrigin === tabOrigin` (v1: no cross-origin frames). The origin sent to the app is
  always this computed one; a field named origin inside the message body is ignored.
- Fill flow: content → `{ kind: "fill_request", nonce, choose, fields }` → background sends `fill` → on success
  `tabs.get(tabId)` and require the tab's origin to still equal the request origin → `tabs.sendMessage(tabId,
  { kind: "fill_result", nonce, username, password, theme }, { frameId })`. On an error code, send
  `{ kind: "fill_error", nonce, code }`. Do not keep the credential in any variable that outlives the handler; never log
  it; never put it in `storage`.
- Save flow: content → `{ kind: "save_candidate", username, password, kind }` → skip when `sender.tab.incognito` →
  background sends `save_candidate` and forgets it.
- Shortcut and context menu: `tabs.sendMessage(tabId, { kind: "begin_fill", choose }, { frameId: 0 })`; the content
  script then starts the normal fill flow itself.

### 10.4 Content script

`detect.ts` — `findLoginForms(root): LoginForm[]` where a `LoginForm` is `{ username?: HTMLInputElement, password?:
HTMLInputElement, newPasswords: HTMLInputElement[], container: Element }`:

- Candidates: `input` elements, including those inside **open** shadow roots (walk recursively).
- Visible means: connected, not `disabled`, not `readOnly`, `getClientRects().length > 0`, width and height at least 8 px,
  computed `visibility` not `hidden`, `opacity` at least 0.1.
- Password field: visible `type="password"`. It is a *new* password when `autocomplete` contains `new-password`, or the
  container has two or more visible password fields.
- Username field: in the same `form` (or, without a form, the nearest common ancestor holding the password field), the
  last visible `input` before the password field in document order with type `text`, `email` or `tel`, or with
  `autocomplete` `username`/`email`.
- Username-only step (no password field visible): a visible input with `autocomplete="username"`, or type `email`, or
  whose `name`/`id` matches `/user|login|email|identifier/i`, inside a form with a submit control.
- Re-run on a `MutationObserver` (debounced 200 ms) for pages that render late.

`icon.ts` — one host element appended to `document.documentElement` with a **closed** shadow root. Inside: a 20 × 20
button with the inline SVG of `app/ui/icons/key.svg`, styled from the theme variables, placed with `position: fixed` at
the right inner edge of the focused login field (username or current password), repositioned on scroll, resize and focus
change, hidden when the field is not visible. The handler ignores events where `event.isTrusted` is false. A click starts
the fill flow for the form of that field. Also a small toast in the same shadow root for errors ("Vaultkeeper is
locked", "No login chosen", "Vaultkeeper is not running") and "TOTP code copied".

`fill.ts` — on `fill_result`: require a pending request with that `nonce` (created by this content script less than 130 s
ago), `location.origin` unchanged since the request, and the target fields still connected and visible. Set a value with
the native setter (`Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(el, v)`), then dispatch
bubbling `input` and `change` events. Fill the password only into `type="password"` fields. Never fill a hidden field. Do
not fill new-password fields. Drop the nonce afterwards.

`capture.ts` — remember, per form, the last values the **user typed** (listen to trusted `input` events; a value we
filled ourselves is marked and does not count as typed). Emit a candidate once per form when: the form fires `submit`; or
a trusted click lands on a submit-like control (`button[type=submit]`, `input[type=submit]`, or a button whose text
matches `/log ?in|sign ?in|continue|next|submit|change|update|save/i`); or Enter is pressed in a password field; or a
typed password field is removed from the DOM or `pagehide` fires. Candidate: `kind: "change"` with the new password when
the form has new-password fields whose values are equal; otherwise `kind: "login"` with the password field. The username
is the form's username field value, or the last username typed on this origin during this page session (for multi-step
logins), or `""`. No password typed by the user → no candidate.

### 10.5 Popup (`src/ui`)

About 320 px wide, `--surface` background, built only from `theme.css` variables. Content by state:

- Not connected: the reason and, for `not_running`/`disabled`, one line saying what to do in the app.
- Site access off: `permissions.contains({ origins: ["https://*/*", "http://*/*"] })` is false (a user can revoke it in
  Firefox, and in Chrome can restrict the extension to "on click"): "Vaultkeeper cannot see web pages. Allow site
  access in the browser's extension settings", with no fill buttons.
- Pairing pending: "Confirm this code in Vaultkeeper" and the fingerprint in monospace.
- Locked: "Vaultkeeper is locked" and an "Unlock" button (`unlock`).
- Unlocked: "Fill this page" (primary), "Choose another login…" (`choose: true`), "Open Vaultkeeper" (`open_app`).
- Footer: the fingerprint, muted, 11 px.

### 10.6 Extension tests (Vite+ `vp test` + jsdom)

`detect`: simple form; no `form` element; username-only step; signup with two password fields; hidden password field
ignored; field in an open shadow root. `fill`: values set and events fired; wrong nonce ignored; changed origin ignored;
password never written to a text field. `capture`: submit emits one candidate; values we filled emit none; change form
emits `kind: "change"`. `router`: forged origin in the body is ignored; cross-origin frame refused; foreign `sender.id`
refused. `pairing`: signature verifies against the exported public key and has 64 bytes. Theme generator test (10.2).
Id-consistency test (section 9).

## 11. Phase 10 — packaging, log, docs

- `scripts/bundle-macos.sh`: no change. The host is the bundled binary itself. The extension is built separately with
  `pnpm -C browsers build`.
- Activity log: a bounded log file `browser` through the existing `BoundedLog` (`app/src/os/log_file.rs`), lines as in
  step 9 of the fill flow plus pairings, removals, refused connections and restored manifests.
- Tray: when at least one browser session is paired and connected, add a disabled menu line "Browser connected: <name>".
- `docs/USAGE.md`: a new section "Browsers" — enabling, installing the extension, pairing and the code, filling, choosing
  another login, saving, the settings, the known limits of section 4, removing a browser.
- `docs/solutions/vaultkeeper-architecture.md`: replace the "Browser-extension bridge" bullet under Decisions with a
  pointer to this file and a five-line summary of D1–D5.
- `README.md`: one feature bullet.

Checks: per phase run only the tests of the crates touched. After phases 3, 5, 6 and 9 run `scripts/check.sh` and
`cargo test --workspace`, and in `browsers/` `pnpm exec vp check && pnpm exec vp test && pnpm exec tsc --noEmit`.
Vite+ documents `vp test` as non-watch by default; import test APIs from `vite-plus/test`.

Manual end-to-end script (run in Chrome and in Firefox, light and dark theme):

1. Enable integration, install for the browser, load the extension. The pair prompt appears with the same code as the
   popup. Deny → the popup says denied. Reconnect, approve → connected.
2. On a site with one saved login: click the field icon → picker → Return → both fields filled, focus back in the browser.
   Click the icon again → filled with no picker.
3. Popup → "Choose another login…" → the picker appears again.
4. On a site with no saved login: picker opens empty; search another item → the "other site" confirmation appears;
   Cancel is the default.
5. Lock the vault, click the icon → lock screen, then picker.
6. Log in to a site with a new account → "Save login?" → Save → the item is in the Manager with the right URI.
   Log in with a changed password → "Update password?". Log in with the saved password → no prompt.
7. "Never for this site" → no further prompt there.
8. Start the host by hand from a terminal → `unavailable/unverified_parent`.
9. Edit the manifest file → next connection restores it and shows the toast.
10. Remove the paired browser in Settings → the popup shows the pairing state again.
11. Quit Vaultkeeper, click the field icon → the app starts in the tray and the flow continues.
12. Switch the app theme to the opposite of the system → picker, prompts and popup all follow the app.

## 12. Review of this plan

Holes found while reviewing, and where the plan closes them:

| # | Hole | Closed by |
|---|---|---|
| 1 | Log output on stdout would corrupt native messaging. | 7.2 stderr writer. |
| 2 | `ui.sock` allows one peer and can dump the vault; reusing it would hand all of that to the browser. | D2. |
| 3 | Anyone can run the host binary and speak for "the browser". | D6, D5, and D3 as the real boundary. |
| 4 | A fake host in the manifest could sit between browser and real host. | Parent check (the real host's parent would not be a browser) and manifest restore, section 9. |
| 5 | An in-page dropdown would give a compromised extension the list of logins, and the page a clickjacking target. | D3, D4. |
| 6 | Remembered approvals keyed by pairing key would let a process that stole the key fill silently. | D7: keyed by live connection. |
| 7 | Save detection as a password oracle. | D8. |
| 8 | Save prompts for every repeated submit, or prompt bombing. | Dedupe HMAC, rate limits, cooldown, "Never for this site". |
| 9 | Tab navigates, or the frame is replaced, between request and fill. | Background and content re-checks, nonce. |
| 10 | Page-supplied text inside trusted prompts. | Prompt content rules in section 4. |
| 11 | `http` pages and scheme downgrade. | 6 (downgrade rule), 8.3 step 1. |
| 12 | Lookalike and IDN hosts. | ASCII host in prompts; other-site confirmation with a safe default. |
| 13 | Domain matching across tenants of a shared suffix (`*.github.io`). | `psl` with the private section; `browser_default_match: Host` for stricter users. |
| 14 | Lock, logout or account switch while a prompt is open. | `deny_all_browser`, re-check before `reveal`, remembered cleared. |
| 15 | Re-prompt items are enforced only in the UI process today. | Picker asks for the master password; remembered never applies to them. See improvement 2 below. |
| 16 | Requests keep the vault unlocked forever. | Only an approved fill counts as activity. |
| 17 | Development builds are not hardened, so the host could be injected. | 8.3 start condition. |
| 18 | The extension's JS strings cannot be wiped. | Stated as a limit; lifetime kept to one hand-off. |
| 19 | Browser service worker restarts drop the connection. | Lazy reconnect; pairing is silent for a known key; only remembered approvals are lost. |
| 20 | Private windows. | Save detection skipped in incognito. |

Still open, to decide with the user before or during implementation:

- **Distribution.** Chrome needs the Web Store or developer mode; Firefox needs AMO signing (unlisted is enough). The
  Chrome extension id depends on the key used; the constant in section 9 must be the id of the build users install.
- **Equivalent domains** (the server's list such as `google.com` = `youtube.com`) are not used. Adding them widens
  matching; leave them out unless asked.
- **Username-less TOTP fill** into one-time-code fields is not planned; the code goes to the clipboard.
- **A password generator for signup forms** (fill a generated password and pre-register it as a save candidate) is a
  natural next step, using the existing generator window.

## 13. Suggested app improvements for safer browser use

Not required for the feature; ordered by value.

1. **Daemon-side Touch ID for fills** is in the plan as an option (`browser_touch_id`). Consider turning it on by default
   when Touch ID is enrolled: it is the one check same-user malware cannot answer.
2. **Enforce master-password re-prompt in the daemon.** Today `reprompt` is checked only in the UI process
   (`app/src/app/reprompt.rs`), and `Call::Reveal` answers for any item. Move the check behind the socket: the daemon
   keeps the set of items verified since unlock and refuses `Reveal`/`Draft` for others. Browser fills then use the same
   gate.
3. **Per-item "never fill from a browser"** flag stored in the app's per-account settings (`Vault::account_settings`),
   for bank and admin logins. The picker shows such items greyed out.
4. **Activity view.** Show the last entries of the browser log in Settings, so an unexpected fill is visible.
5. **Clear remembered approvals after idle.** Besides lock and sleep, forget them after 15 minutes without a fill.
6. **Refuse outdated extensions.** Keep a minimum `extension_version` in the daemon and answer `prove` with a clear error
   below it, so a fixed extension bug cannot be re-used with an old build.
7. **Developer ID signing and notarization** when an Apple Developer account becomes available. A designated requirement
   by team id would then also let the host check be expressed without cdhash pinning, and Gatekeeper would cover the
   bundle the manifests point to.
8. **Warn on reused or weak passwords at save time** in the save prompt (the daemon already has both values in hand).
9. **Honour `autofillOnPageLoad` never.** Keep D10 even if asked for convenience; offer the shortcut instead.

## 14. Verified facts (Phase 0)

Run on 2026-11-10 on this Mac (Chrome 157.0.8103.39, Firefox 159.0.1). The throwaway code is in
`experiments/browser-spike/` (host, both extensions, logs `host-run1.log`), `experiments/focus-spike/` and
`experiments/psl-check/` (all gitignored).

**Status: Phase 0 is finished** (2026-11-10). The Chrome checks and the focus test (section 8.4) are done.
Still unverified, none blocking: Brave, Edge and Chromium signatures (excluded from version 1), Firefox key
persistence across a restart, and the Firefox idle port with a normally installed add-on (Phase 7).

Done on 2026-11-10: the **focus test** (section 8.4). The other app stayed frontmost in all variants; the remaining
risk is checked by hand in Phase 5.

**Phases 1 and onward can start.**
Everything in Phase 0 is recorded below. The Chrome checks needed a person to load the spike extension once, because
branded Chrome refuses `--load-extension`; `experiments/browser-spike/chrome-spike.sh` repeats them.

| Fact | Result |
|---|---|
| Host parent process, Firefox | The direct parent is the main process, `/Applications/Firefox.app/Contents/MacOS/firefox`: no helper, no shell in between. The walk-up-two-ancestors fallback of section 5 is not needed for Firefox. |
| Host parent process, Chrome | Measured: the direct parent is the main process, `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`, no helper in between (also after a reload). The parent check works as written. |
| Host arguments, Firefox | Exactly two: the full path of the manifest (`~/Library/Application Support/Mozilla/NativeMessagingHosts/<name>.json`) and the add-on id. The `cli.rs` detection of section 7.2 is right. |
| Host arguments, Chrome | Measured: exactly one, `chrome-extension://<id>/` **with** the trailing slash. Section 7.2 already accepts it. |
| Signature, Chrome | Identifier `com.google.Chrome`, team `EQHXZ8M8AV`, hardened runtime plus library validation. Chrome's own designated requirement also accepts `com.google.Chrome.beta`, `.dev` and `.canary`. |
| Signature, Firefox | Identifier `org.mozilla.firefox`, team `43AQ936H96`, hardened runtime. |
| Requirement strings against live processes | `codesign --verify -R='identifier "<id>" and anchor apple generic and certificate leaf[subject.OU] = "<team>"' <pid>` (a plain pid; `+pid` does not work): satisfied by the running Chrome and Firefox main processes; fails for a wrong team id, for the other browser's requirement, and for a Chrome helper. This is the same check the host will do with `SecCodeCopyGuestWithAttributes`. |
| Brave, Edge, Chromium | Not installed here, signatures **not verified**. Excluded from version 1 (section 7.3). |
| Native port keeps the background alive, Chrome | Measured: a host started after a reload stayed connected with no traffic for 510+ s (past the old 5-minute limit), so an open port keeps the worker alive. If the host dies the port closes and the worker stops, so `onDisconnect` must be handled (it is, section 10.3). Note: reloading the extension closes the port, and the host sees stdin close (it exited at +45 s, as expected). |
| Native port keeps the background alive, Firefox | Measured: an idle port (no messages, no heartbeat) stayed open for 705 s until the browser was killed, so the 30 s event-page timer did not drop it. **Caveat:** web-ext holds a remote-debugging connection, and an attached debugger can keep an event page alive. Repeat in Phase 7 with a normally installed add-on; if the port drops, add a host heartbeat (a `{"event":"ping"}` every 20 s while connected). MDN's pages contradict each other on this ("a background page does not unload until all … message ports are closed" versus "message ports cannot prevent an event page from shutting down"). |
| Firefox MV3 background | `background.scripts` with `"type": "module"` works (loaded and ran). `background.service_worker` is **not supported** in Firefox, so two manifests are right. Browser-compat data: module background scripts need Firefox 112+, Chrome 92+. Use `strict_min_version` `128.0`. |
| Firefox MV3 host permissions | From Firefox 127 the patterns in `host_permissions` and `content_scripts` are shown in the install prompt and granted at install; Firefox 126 and earlier did not grant them. That is why `strict_min_version` is `128.0`. Users can still revoke site access later, so the popup must detect it (`permissions.contains`, section 10.5). From MDN and the Firefox Extension Workshop migration guide; not tried by hand. |
| Non-extractable key in IndexedDB, Firefox | Works in the event page: key pair generated and stored, public key 65 bytes starting `0x04`, ECDSA P-256 signature 64 bytes (IEEE P1363), `verify` true, exporting the private key refused. Persistence across a restart was not tested (the profile was temporary). |
| Non-extractable key in IndexedDB, Chrome | Works: 65-byte public key, 64-byte signature, verify true, private export refused. After an extension reload the same key was found (`"created":false`) and still signed and verified. |
| Chrome `--load-extension` | Refused in branded Chrome even with `--disable-features=DisableLoadExtensionCommandLineSwitch`. Manual loading only (section 10.1). |
| Chrome native-messaging directory with `--user-data-dir` | **Open, and not needed by the plan** (the app registers manifests in the default folders). It only matters for automated runs on a throwaway profile; `chrome-spike.sh` registers the manifest in both places, so its result cannot answer this. |
| Firefox manifest location on macOS | `~/Library/Application Support/Mozilla/NativeMessagingHosts/<name>.json` works (the host started from it). |
| Existing manifests on this Mac | `com.8bit.bitwarden.json` in the Chrome, Chromium, Edge and Firefox folders and a Claude one in Chrome and Chromium. Different names from `org.vaultkeeper.browser`, so no clash. |
| Non-activating Slint window | **Partly verified**, see the end of section 8.4. Daemon-style backend (Accessory, no activation at launch): `show()` leaves the other app frontmost, window visible at level 3. Default backend (activates at launch): `show()` makes the app frontmost. The real UI-process setup (Accessory plus activation at launch) and the hand-back fallback are **untested**: the one attempt ran on a locked Mac. `with_active(false)` in the attributes hook made no difference in either run. First-click behaviour untested. |
| `psl` | `psl = "2.1"` (tested `=2.1.250`). The list is compiled in; the build needs no network. The private section is included: `alice.github.io` and `bob.github.io` have different registrable domains, `github.io` itself has none, `foo.blogspot.com` is its own domain. IPs and unknown suffixes need handling before calling it (section 6). |

## 15. Firefox end-to-end run (2026-11-11)

`scripts/e2e-browser.sh` runs the real Firefox 159 extension (headless, WebDriver with real trusted input) against a
real `vaultkeeper --daemon` (`vw-it` debug build, private data dir and keychain prefix) and a disposable Vaultwarden. The
driver is `browsers/e2e/run.mjs`; `app/examples/e2e_browser_bot.rs` plays the `--ui` process. It needs
`npm i selenium-webdriver` in a scratch directory (`E2E_DEPS`) and a geckodriver binary (`GECKODRIVER`); it is not part of
`vp test`. Result: pair (code equal in prompt and popup), fill (picker, remembered), popup "Choose another login…", save
(new, update, unchanged = no prompt), lock → `UnlockInTray` → picker, removed pairing, daemon killed and restarted, idle
port over 100 s, host stdout framing: all pass.

Facts learned:

- **Firefox ignores `$HOME` for native-messaging manifests.** `XREUserNativeManifests` is `~/Library/Application
  Support/Mozilla/NativeMessagingHosts` of the real account. The run overrides the directory-service key from a
  privileged WebDriver context (`geckodriver --allow-system-access`, `Services.dirsvc.set`), so no real file is touched.
- Verified: the host's parent is the real Firefox (the verified-parent check is on and the pairing stores
  `browser: "firefox"`); `runtime.id` read in the popup equals `browser-extension@vaultkeeper`, which is the caller the
  host signs; the host's stdout holds only framed native messages (a host started from a terminal answers exactly one
  `unavailable/unverified_parent` frame, 56 bytes, empty stderr); the host's RSS is about 20 MB (debug build).
- With the daemon down, the host started by Firefox starts `vaultkeeper --tray` itself (observed in the daemon-killed
  scenario). In a test it must inherit the headless/keychain-prefix overrides, or it would start a real tray app.
- A temporarily installed add-on (WebDriver) kept its idle native port for 100 s, past the 30 s event-page timer. The
  remote-debugging caveat of section 14 still applies, so a normally installed add-on is still unverified.
- The popup page cannot be opened in a tab for testing: the background refuses senders that have a `tab`. The run opens
  the real toolbar popup instead and reads it through a frame script.
- A daemon whose data directory was deleted while it runs does not exit on SIGTERM (the single-instance listener thread
  cannot be woken); harmless in practice.
- Not logged in `browser.log`: pairings, removals and refused connections (only fills and restored manifests are).
