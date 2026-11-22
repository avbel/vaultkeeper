# Vaultkeeper on macOS (Apple silicon)

## Build and install

```sh
cd ~/Projects/vaultkeeper
scripts/make-signing-cert.sh   # once; asks for your login password to trust the certificate
scripts/bundle-macos.sh        # -> target/bundle/Vaultkeeper.app
ditto target/bundle/Vaultkeeper.app /Applications/Vaultkeeper.app
open /Applications/Vaultkeeper.app
```

`make-signing-cert.sh` is optional, but recommended. It creates a self-signed "vaultkeeper local"
code-signing certificate, so every rebuild has the same code identity. Without it the bundle is
ad-hoc signed. macOS then asks again "vaultkeeper wants to use your confidential information" for the
keychain item (the refresh token) after each rebuild.

**Signing prompt.** `bundle-macos.sh` shows a keychain prompt ("codesign wants to sign using key
…") on every build. Click **Allow**, not *Always Allow*. The prompt is the protection: Vaultkeeper's
keychain items trust anything signed as "vaultkeeper local", so a key that signs without asking
would let any process sign its own binary as Vaultkeeper and read the refresh token silently.
*Always Allow* re-creates exactly that. While creating the certificate the script also asks once
for your login keychain password (`security set-key-partition-list`); without that step the
codesign prompt rejects even the correct password. If your certificate was made by an older version of the
script (which trusted `codesign` without a prompt), run `scripts/make-signing-cert.sh --recreate`
once; Vaultkeeper then asks one more time for its keychain items after the next build.

The app has no Dock icon. It lives in the menu bar; a Dock icon appears only while the vault
window is open.

Update: quit Vaultkeeper from the tray menu **first**, then rebuild, `ditto` it again and open it.
The background process only accepts a window process with exactly its own code signature, so
a running old version refuses the new one's windows until it is quit.

## First login

1. Open the app; the login window appears.
2. Enter the **server URL** of your Vaultwarden (e.g. `https://vault.example.com`), email and master
   password. Plain `http://` is accepted only for localhost and private-network addresses
   (10.x, 172.16–31.x, 192.168.x, `*.local`).
3. If the account has two-step login, enter the code from your authenticator app or the email. If
   the server asks for a new-device code, enter that.
4. The vault syncs and the Manager window opens.

**Security key (FIDO2 / U2F, e.g. YubiKey).** Add the key once in the web vault (Settings →
Security → Two-step login → Passkey). When it is one of your two-step methods,
the login window starts with it: plug the key in over USB and touch it, and enter its PIN if it
asks. *Use security key* tries again; the other methods stay available above. The server URL must
have the same scheme, host and port as the server's `DOMAIN` setting, or the server refuses the
key's answer. NFC and Bluetooth keys are not supported.

More accounts: tray menu or sidebar account switcher → *Add account*. *Log out* removes all of that
account's local data: cache, keychain items, Touch ID enrollment, SSH keys in the agent and the
clipboard if it holds a copied secret.

## Daily use

- **Quick Panel:** ⌘⇧Space (Settings → Shortcuts), the tray icon → *Quick search*, or
  `vaultkeeper --search` (bind it to a launcher shortcut). Type, then:
  - Enter copies the password;
  - ⇧Enter copies the username;
  - ⌘Enter copies the TOTP code;
  - ⌘⇧Enter, or the *Auto-type* button on a login row, types the username, Tab and the password
    into the app that was in front when you opened the panel (see *Auto-type* below).
- **Edit conflicts:** if the item changed on another device while you were editing, saving is
  refused with a message; your typed values stay in the form, Cancel loads the latest version.
- **Manager window:** every row has one-click copy buttons for username, password and TOTP (with a
  countdown ring). The sidebar has folders (create, rename, delete), organizations and collections,
  and kinds. The detail pane edits items and attachments.
- **Collections:** the detail pane's *Move to organization…* moves a personal item into an
  organization's collections, as the official clients' *Assign collections* does. This can't be
  undone: the item can't go back to your personal vault or to another organization. On an
  organization item, *Change…* changes which of its collections it is in. Read-only collections
  stay assigned. An item from before per-item keys that has attachments can't be moved here; use
  the official client for those.
- **Send.** Choose *+ New ▸ Send* (or ⌘N in the Send list), then select *Text* or *File*.
  Enter your text or choose one file up to 100 MB. Give the Send a name, choose when it will be
  deleted (1 hour to 30 days), and optionally set a password, a view limit, *Hide my email*, or
  a private note. Vaultkeeper encrypts the content and copies the link after saving. The row's
  link button or Enter copies it again. Recipients open the link in your server's web vault.
  Share any password separately. You can edit a Text Send and keep its link working.
  *Remove password* and *Delete* are available for both types.
- Copied secrets are hidden from clipboard history, and cleared after 30 s (configurable) if the
  clipboard still holds them. The background process does the clearing, so it happens even when
  the windows have closed, and also on lock, log out, account switch and Quit. Time asleep counts.
- **Generator:** in the tray menu, its own global hotkey if you set one (Settings → Shortcuts), and
  the *Generate* button on the password field when editing an item.
- **Settings:** tray menu → *Settings…*, or ⌘, in the Manager.
- **Sync:**
  - live through the server websocket;
  - also on unlock, every 30 min and *Sync now*;
  - the tray's *Sync now* reads *Syncing…* while it runs, and an open Manager shows *Vault synced*
    or why it failed. Under it the tray menu shows *Last synced 12:04* (the date too, if it was
    not today), or the failure until a later sync succeeds.
- **Offline:** when the server can't be reached the app keeps working from the encrypted cache. A
  toast tells you so, and it syncs as soon as the server is back.
- **Lock:** after *Lock after* of inactivity (Settings → Security; *Never* turns the timer off), on
  sleep or screen lock while *Lock on sleep or screen lock* is on (the default), or from the tray.
  A settings file from an older version with *On sleep / screen lock* becomes *Never* plus that
  switch.
- **Broken settings file:** if `settings.json` cannot be read, Vaultkeeper starts with the defaults,
  keeps the old file as `settings.json.broken` and says so once in a window toast.

## Auto-type

Open the Quick Panel with the hotkey (or the tray) while the login form is in front, pick the
login and press ⌘⇧Enter or its *Auto-type* button. The panel closes, the previous app comes back
to the front and Vaultkeeper types `username`, Tab, `password` as key presses (only the password when
the username is empty). Nothing goes through the clipboard. It works for logins with a password.

- Items with *Ask for master password* need it first: open them in the Manager (⌘O) and confirm,
  then *Auto-type* works until the vault locks.
- Typing starts once you let go of ⌘ and ⇧. It stops, and the next window says why, when the app
  does not come back to the front within a second, when another app (or Vaultkeeper) comes to the
  front while typing, when a modifier key is held down, or when the vault locks.
- Opened with ⌘K from the Manager there is no other app to type into; in the Manager ⌘⇧Enter
  opens the item's URI.

**Accessibility permission.** macOS lets an app send key presses to other apps only with the
Accessibility permission. The first *Auto-type* shows the system's request; allow Vaultkeeper in
System Settings → Privacy & Security → Accessibility, then try again. Nothing is typed until it is
allowed. macOS ties the permission to the app's code signature: a build signed with the
"vaultkeeper local" certificate (`scripts/make-signing-cert.sh`) keeps it across rebuilds; an
ad-hoc signed build is a new app to macOS after each rebuild, so remove the old Vaultkeeper entry
from the list and allow it again.

## Copying on Linux

On KDE, Sway and Hyprland a copy needs no permission: the compositor's data-control protocol takes
it, marked as a secret so clipboard history skips it.

GNOME has no such protocol, so Vaultkeeper copies through the desktop's RemoteDesktop portal, the
only route GNOME gives a background program to the clipboard. The first copy opens GNOME's
*Remote Desktop* dialog:

1. Switch on **Allow Remote Interaction**. GNOME keeps *Share* disabled until you do; there is no
   clipboard-only choice in that dialog.
2. Leave **Clipboard** switched on and press **Share**.

That switch also allows Vaultkeeper to send keyboard input. The copy path never sends any; the
keyboard is in the request only because GNOME stores no grant for a session without a device and
would then ask on every start. The portal offers no way to state a purpose in the dialog, so it
shows none. The grant is kept (`clipboard-portal-token` in the data directory) and later copies ask
nothing; revoke it in the desktop's privacy settings. GNOME shows its orange remote-session
indicator while Vaultkeeper holds the session.

While the dialog is open the Manager and the Quick Panel say *Waiting for clipboard permission*,
and the value lands when you press *Share*; the clear countdown starts then. If you close the
dialog, or leave it unanswered for three minutes, the copy falls back to the plain X11 clipboard
when the session has one (clipboard history may record it there) and fails with a message
otherwise. Vaultkeeper does not ask again for five minutes.

GNOME keeps its own copy of whatever is on the clipboard and offers it again when the owner
lets go. When the clear time comes Vaultkeeper therefore first replaces its selection with an
empty marker, which makes GNOME drop that copy, then releases it and checks what the desktop
reports. If the clipboard still offers the value, the log says the clear failed instead of
reporting it done. A Vaultkeeper that is killed cannot do this, and GNOME then keeps the value.

Limits of that check:

- Clipboard history may already hold the value. Only KDE and the wlroots compositors honour the
  secret mark; a GNOME history extension (GPaste, Clipboard Indicator) records the copy when it is
  made, and clearing the clipboard does not remove it from that history.
- The check looks at what the desktop reports within a quarter of a second after the release. A
  history extension that puts the value back later than that is not noticed.
- It reads back only `text/plain` types. An X11 program that offers the value only as
  `UTF8_STRING` or `STRING` is not recognised as offering text.
- A copy you make in another program is left alone when the clear time comes. If you make it in
  the instant the clear runs, before the desktop has told Vaultkeeper about it, the clear can
  still replace it.

## Auto-type on Linux

Auto-type works in Wayland sessions only; the shortcut is Ctrl+Shift+Enter. Vaultkeeper tries two
routes and the first that works types:

1. **GNOME and KDE:** the RemoteDesktop portal. The first use shows the desktop's "allow keyboard
   control" dialog; the grant is stored (`autotype-portal-token` in the data directory) and later
   uses ask nothing. Revoke it in the desktop's privacy settings. Closing the dialog stops that
   attempt, and Vaultkeeper does not ask again for five minutes.
2. **Sway and Hyprland:** a virtual keyboard (`zwp_virtual_keyboard_v1`, served by wlroots-based
   compositors only), with a keymap generated for the text, so the keyboard layout does not matter
   there and non-ASCII characters work. There is nothing to allow.

On GNOME and KDE the desktop looks each character up in the keyboard layout that is active and
drops one the layout lacks, and the portal offers no way to choose the layout. So Vaultkeeper reads
the session's keymap while the Quick Panel still has the focus and types only when every character
of the login comes out right in the active layout; otherwise it types nothing and says why (for
example `Ж` or `ö` on a US layout, Latin letters while a Russian layout is active, or Caps Lock
being on). Switch to a layout that has all the characters, or copy the password instead. A login
whose characters are spread over two layouts cannot be auto-typed there. With GNOME's "switch input
sources individually for each window", the target window's layout is unknown, so the text must be
typeable in every configured layout. Where the compositor also has a virtual keyboard, a login the
portal route refuses because of the layout is typed through that instead; with Caps Lock or another
locked modifier on, nothing is typed by either route.

The check has limits. The layout can still change between the check and the last key, for example
when you switch it while the text is being typed or while the first-use permission dialog is open
(it waits up to 180 seconds). XKB options that switch the layout with a key (such as
`grp:lshift_toggle`) and sticky keys are not modelled. On GNOME with more than four input sources,
or with per-window sources, the target window can get a keymap that was not the one checked.

Where neither exists the window says why (for example that the compositor has no virtual keyboard).
X11 sessions are not supported.

Wayland does not let an app focus another app's window, so the previous window cannot be brought
back as on macOS. Vaultkeeper closes the Quick Panel first, waits a moment for the compositor to
focus the window that was in front, and then types. If you moved the focus meanwhile (a click, a
new window), the text goes to whatever has the focus, so wait for the panel to close before
touching anything. Held modifier keys would be applied to the typed keys (Ctrl+Shift turns Tab
into Ctrl+Tab), so Vaultkeeper keeps the panel open until it sees the keys released and gives up
after two seconds with "Release the shortcut keys and try again". (This wait watches the panel's
own modifier state and has not been verified on a live session yet.) If a Vaultkeeper window has
the focus when you open the panel there is no target and nothing is typed. Typing stops, and the
next window says why, when the vault locks. The panel cannot know which window will receive the
text, so it never says `typing into <app>`.

## Touch ID

Settings → Security → Touch ID → *Enrol* (while unlocked).
- The user key is wrapped to a Secure Enclave key that only works with your currently enrolled
  fingerprints.
- Adding or removing a fingerprint disables Touch ID unlock: unlock with the master password and
  enrol again.
- *Require master password on app start* (off by default) forces the password after every launch.
- *Unlock with Touch ID right away* (off by default; available once Touch ID is enrolled) skips
  the lock window: opening the vault, *Unlock* in the tray, the Quick Panel hotkey, *Ask to unlock
  on start* and an SSH request while locked start the Touch ID prompt at once, and on success go
  straight to what you asked for (Manager, Quick Panel, SSH approval). Cancelling or a failure
  opens the usual lock window (the Quick Panel with its password field for the hotkey); after a
  cancel or failure it does not ask again while that window is open. A cancel shows no error;
  other failures show the reason.
  With *Require master password on app start* the first unlock after launch still needs the
  password. Locking (timer, sleep, ⌘⇧L) never starts a prompt by itself.

## SSH agent

The agent is off by default. Settings → SSH agent → turn on *SSH agent* (the socket path has a copy button there). The keys come from the vault's SSH-key items. The socket is
`~/Library/Application Support/vaultkeeper/ssh-agent.sock`.

Your `~/.ssh/config` currently points every host at the App Store Bitwarden agent:

```
Host *
    IdentityAgent ~/Library/Containers/com.bitwarden.desktop/Data/.bitwarden-ssh-agent.sock
```

To switch to Vaultkeeper, change that line to:

```
    IdentityAgent "~/Library/Application Support/vaultkeeper/ssh-agent.sock"
```

Rollback: restore the old line.

To try it without editing the config:

```sh
SSH_AUTH_SOCK="$HOME/Library/Application Support/vaultkeeper/ssh-agent.sock" ssh-add -l
ssh -o 'IdentityAgent "~/Library/Application Support/vaultkeeper/ssh-agent.sock"' -T git@github.com
```

Each sign request opens an approval window (process and key fingerprint, auto-deny after 30 s).
- *SSH requires Touch ID* asks for a fingerprint after you click Approve.
- *SSH requires approval* can be set to *Remember until lock*, or tick *Remember for this key until lock*
  in the prompt; that key is then not asked again until the vault locks.
- The agent holds keys only while the vault is unlocked. While it is locked, `ssh-add -l` or a
  connection shows the unlock window first and continues after you unlock. While logged out the
  agent lists no keys.

### SSH agent on Windows

The agent listens on the named pipe `\\.\pipe\openssh-ssh-agent`, which is where Windows OpenSSH
(`C:\Windows\System32\OpenSSH\ssh.exe`) looks, so there is no `IdentityAgent` line or
`SSH_AUTH_SOCK` to set. Settings → SSH agent shows the pipe name instead of a socket path.

- The built-in *OpenSSH Authentication Agent* service uses the same pipe name. Stop and disable it
  (`Stop-Service ssh-agent; Set-Service ssh-agent -StartupType Disabled`), or Vaultkeeper's agent
  cannot start. If it is still running, Settings shows that message and turns the
  toggle back off; run those two commands in an administrator PowerShell, then turn the agent on again.
- Git for Windows bundles its own `ssh`, which does not use the pipe. Point Git at the Windows one:
  `git config --global core.sshCommand C:/Windows/System32/OpenSSH/ssh.exe`.
- WSL cannot open a Windows pipe directly; it needs a relay such as `npiperelay` that exposes the
  pipe as `SSH_AUTH_SOCK` inside the distribution.
- *SSH requires Windows Hello* asks for a Windows Hello gesture (face, fingerprint or PIN) after
  you click Approve.

## Browsers

Chrome, Edge and Firefox can fill logins from Vaultkeeper and offer to save new or changed passwords. The
browser extension is a thin client: it holds no password, key or copy of the vault. Matching, every
decision and every prompt are in Vaultkeeper's own windows.

1. Settings → Browsers → turn on *Browser integration*, and leave *Install for …* on for the browsers
   you use. This writes the native messaging connection file for each installed browser
   (`~/Library/Application Support/<browser>/NativeMessagingHosts/org.vaultkeeper.browser.json`).
   Integration starts only with the signed app build; otherwise the state line says why.
2. Install the extension (see `browsers/README.md`; Edge installs it from the Chrome Web Store after you
   allow extensions from other stores) and open its popup. The first connection opens a
   *Connect <browser>?* window with a code. Check that it matches the code in the extension popup,
   then click *Connect*. *Deny* is the default; Return does not approve.
3. **Fill:** click the Vaultkeeper icon in a login field, press ⌘⇧L, or use the popup's *Fill this
   page*. A native window lists the logins saved for the site; pick one with the arrows and Return.
   When only one login matches the site it is filled at once, with no window (see the setting below).
   Later fills of the same site in the same browser session need no window until the vault locks, the
   Mac sleeps or the screen locks. *Choose another login…* in the popup always shows the window.
   Picking a login saved for a different site asks for a second confirmation (the default is *Cancel*).
   After you confirm, a small *Add this address?* window may offer to add the site to that login so
   it matches (and fills at once) next time. It is offered only when one of the login's saved
   addresses has exactly the same site name under another ending: `site.com` and `site.io`, or
   `example.co.uk` and `example.com`. A different name such as `site.another.com`, a lookalike with a
   different letter (`sitе.com` with a Cyrillic "е") and sites on shared hosts such as `github.io`
   are never offered. Nothing is changed unless you click *Add*, and *Not now* is not asked again
   for that login and site until Vaultkeeper restarts.
   Logins that require the master password ask for it in the window.
4. **Locked vault:** a fill shows the unlock window first and continues after you unlock.
5. **Save:** after you sign in with a new account or a changed password, a small *Save login?* or
   *Update password?* window appears in the top-right corner without taking focus from the browser,
   so answer it with the mouse. It also times out after 30 s (*Not now*). *Never for this site*
   stops the offers for that site. Nothing is offered in private windows, on unencrypted sites other
   than local ones, or when the stored password is already the same.
6. **New passwords:** on a sign-up or change-password form, click the shield in the new password
   field and choose *Use a strong password*. Vaultkeeper generates one with your Generator settings,
   fitted to the field's length limits (a passphrase that does not fit becomes a password), and fills
   it into the password and repeat-password fields. A locked vault shows the unlock window first.
   When you submit the form, *Save new login?* (or *Update password?* on a change form) appears even
   if *Offer to save logins* is off; *Never for this site* still applies. A form with neither a
   username nor a current-password field may be a sign-up or a reset by email link, so *Save
   password?* lets you pick one of the site's logins or *New login* (saved without a username).
   Only the field you opened the menu on and empty password fields are filled. In a private window
   the password is filled and listed in the Generator, but no save is offered. Until a login holds it, the password is kept sealed with
   your vault key for 24 hours, also through a lock, and listed under *Unsaved passwords from
   websites* in the Generator window, where you can copy it, save it as a login or remove it. Log
   out, switching accounts and quitting the app drop the list. A page that changes the filled value
   gets a warning and no save offer. The page's `passwordrules` and `pattern` attributes are not
   read yet; only `minlength` and `maxlength` are.
7. **Passkeys:** when a site creates a passkey, a *Save passkey?* window offers to keep it in a
   new login or in one of the site's logins (the one with the same account name is chosen if there
   is one; a login that already holds this site's passkey, or that asks for the master password,
   is not offered). When a site asks for one the vault holds, *Sign in with a passkey?* lists them.
   Both windows work like the save window (no focus taken, 30 s), and both ask for Touch ID before
   anything is signed or stored. Passkeys are stored as the Bitwarden clients store them, so
   passkeys made here work in Bitwarden and the other way round. Everything else goes straight to
   the browser's own passkey dialog, so a security key keeps working as before: *Not now*, a
   refused Touch ID, a Mac without Touch ID, a locked vault (unlock Vaultkeeper and try again), a
   site the vault holds no passkey for, a site that asks for a security key, logins that ask for the
   master password, and requests from a frame of another site. Passkeys in the username field's
   suggestion list (conditional mediation) are left to the browser too. Turn off *Save and use
   passkeys* in Settings → Browsers to leave every site to the browser's own passkeys.
8. **Settings:** *Require Touch ID to fill* (asked for every fill, including remembered ones and single matches), *Fill at once when only one login matches* (on by default: with exactly one saved login for an encrypted page, no picker is shown; sites with several matches, `http` pages and re-prompt items still show it),
   *Fill remembered logins when a page opens* (off by default: a login you picked before is filled as an encrypted
   page loads, with no click, only while the vault is unlocked and Touch ID is not required; the trade-off is that
   scripts on that page can read what was filled without you asking for it),
   *Offer to save logins*, *Copy TOTP code after filling*
   (the code goes to the clipboard and is cleared like other copies) and *Match sites by* (*Domain*
   or *Exact host*, for saved addresses without their own rule; a saved address's own match
   rule from the Bitwarden web vault always wins). *Paired browsers* lists each connection with its
   fingerprint and a *Remove* button; removing it closes that browser's live connection.

The activity log is `~/Library/Logs/vaultkeeper/browser.log`: time, browser, host and item id of
every fill and how it was released (`picker`, `remembered`, `single` or `auto`), never a secret.

The login you pick for a site is remembered for that paired browser until you log out, so the next fill on the
same site skips the picker, also after restarting the browser or the app and after the vault was locked. Logging
out, switching accounts and removing the browser under *Paired browsers* forget it. Touch ID, if required, is still
asked for.

Known limits:

- Malware running as your macOS user can drive a real browser with a copied profile, so pairing and
  the browser signature check are barriers, not guarantees. Nothing is released without a click in a
  Vaultkeeper window, and a remembered login belongs to one paired browser and ends at log out.
- A filled password can be read by scripts of the page it was filled into (for example after XSS).
- JavaScript strings cannot be wiped; the extension keeps a credential only for one message hand-off.
- The parent-process check can be bypassed by starting the host and then replacing its parent.
- Equivalent-domain lists are not supported. Filling on page load is off unless you turn on *Fill remembered logins when
  a page opens*; it covers only remembered picks on encrypted pages, never asks to unlock, and never starts the app on a
  page load. The extension connects when the browser starts (only once it has been paired before; this starts the app
  if it is closed, as a click on the extension does), and a fill on a restored tab waits up to 3 s for that connection.

To remove a browser, turn off *Install for …* (the connection file is deleted), remove the pairing,
and remove the extension in the browser.

## Start at login

Settings → Security → *Start at login*. This installs `~/Library/LaunchAgents/vaultkeeper.plist`, which
starts `vaultkeeper --tray`, so only the menu bar icon shows. *Ask to unlock on start* opens the unlock
window at launch. With no account added yet, the sign-in window opens instead.
- Enable it from the copy in `/Applications`, because the agent stores the path of the executable
  that enabled it.
- To remove it: turn the setting off, or `rm ~/Library/LaunchAgents/vaultkeeper.plist`.
- After a crash macOS starts Vaultkeeper again (`KeepAlive` on a failed exit); *Quit* from the tray
  stays quit. An agent written by an older version is updated on its next start at login.

## Lock on Linux

Vaultkeeper follows `systemd-logind` and the desktop's screensaver service, so sleep, logout and a
screen lock from GNOME, KDE, Omarchy or `loginctl lock-session` lock the vault. Sway and Hyprland
have no screensaver service: make the idle daemon lock through logind, so Vaultkeeper hears it.

```
# sway: ~/.config/sway/config (the `lock` hook fires on logind's Lock signal)
exec swayidle -w lock 'swaylock -f' before-sleep 'loginctl lock-session' \
    timeout 300 'loginctl lock-session'

# hyprland: ~/.config/hypr/hypridle.conf
general {
    lock_cmd = pidof hyprlock || hyprlock
    before_sleep_cmd = loginctl lock-session
}
listener {
    timeout = 300
    on-timeout = loginctl lock-session
}
```

## System protection

Settings → *System protection* (at the bottom, closed until you open it; Linux only) lists what
Vaultkeeper uses on this computer to keep your vault away from other programs. The header counts
the protections: `7 of 9 protections active · 1 limited · 1 off`. Each row says what it protects
you from, how it is used here and, in small type, the technical name. Anything that needs a look
is repeated first under *Needs attention*, with a *How to turn it on* list when there is
something to do. *Re-check* probes again after you fixed something, *Copy details* copies the
report for a bug report.

| State | Meaning |
| --- | --- |
| Active | The strongest mechanism is in use, no caveat. |
| Limited | It works, with a stated weakness (for example sign-in data sealed by a host key only). |
| Off | Not in use; Vaultkeeper still runs. The app sandbox is Off until you turn it on. |
| Missing | A required protection has no working mechanism; the start was overridden. |

The desktop integration rows (tray icon, desktop portal, notifications, global shortcuts) are
listed but not counted in the header.

`vaultkeeper security status` prints the same rows and header; `vaultkeeper security status
--technical` prints the raw chain table, and `vaultkeeper security requirements` says what
Vaultkeeper needs from the system and how to fix it. The sandbox, memory-reading and shortcut rows
exist only in the running app, so the command names them and points to Settings.

When a required protection is missing, Vaultkeeper refuses to start and prints why. Two ways to
start anyway:

- `vaultkeeper --skip-security-issues` starts once.
- `vaultkeeper security accept` accepts the issues refused right now for every later start (the
  list shows under *Accepted issues* in Settings and takes effect at the next start). A new issue
  refuses again.

A window of a process started this way carries the "Security issues skipped" badge.

### Turning the app sandbox on

The Landlock sandbox is off by default, because it also blocks opening files outside
Vaultkeeper's own folders. To turn it on for every start:

1. Create `~/.config/environment.d/vaultkeeper.conf` with one line: `VAULTKEEPER_LANDLOCK=1`
   (`mkdir -p ~/.config/environment.d && echo VAULTKEEPER_LANDLOCK=1 > ~/.config/environment.d/vaultkeeper.conf`).
2. Log out and back in.
3. Open System protection again: *App sandbox* should read Active.

`environment.d` reaches programs started by the systemd user manager (GNOME, KDE Plasma, Hyprland
through UWSM). On plain Sway also add `export VAULTKEEPER_LANDLOCK=1` to `~/.profile`. To try it
once first, quit Vaultkeeper and run `VAULTKEEPER_LANDLOCK=1 vaultkeeper`. With the sandbox on,
attach files from inside `~/.cache` or Vaultkeeper's own folders. Do not edit Vaultkeeper's
`.desktop` files: the app rewrites them.

### Sealing sign-in data to a security chip

*Sign-in data on disk* is Limited when `systemd-creds` has only the host key. Check
`systemd-creds has-tpm2`; if the firmware has a TPM that is off, enable "TPM 2.0" (fTPM, PTT) in the
UEFI setup, or add a virtual TPM to a virtual machine. Vaultkeeper looks for the chip only when
it starts, and data already on disk keeps its old key until it is saved again, so restart
Vaultkeeper and sign out and in to re-seal it now.

## Updates

The tray item above *Quit* checks for a new release on GitHub. Settings → Security → *Update automatically*
(on by default) checks once a day, downloads a new version in the background and installs it once the
vault is locked and no window is open; Vaultkeeper then restarts in the menu bar and you unlock it as
after any restart. With the setting off, nothing is checked until you click *Check for Updates…*, and a
downloaded update waits for *Install Vaultkeeper X and Restart*.

- An update installs only when it is signed with the same certificate as the running app and uses the
  hardened runtime; anything else is discarded. It is unpacked and checked in
  `~/Library/Application Support/vaultkeeper/update/`, then swapped into place in one step.
- Updates downloaded by the app are not quarantined, so macOS does not ask to confirm them again.
- If macOS refuses to replace the app, or a copy cannot replace itself, the item only offers *Download Vaultkeeper X…*, which opens the release page:
  for example a copy run from the disk image or from Downloads, one in a folder you may not write to (a standard
  account and `/Applications`), or a build signed ad hoc.
- The previous version stays in `update/previous.app` for a minute after the restart. If the new one
  does not start, quit Vaultkeeper and move `previous.app` back to `/Applications/Vaultkeeper.app`.
- When the running copy was started at login (by launchd), it exits with status 75 so that launchd
  starts the new one; otherwise it opens the new one itself.

## Themes

Settings → Appearance → Theme: *System* (follows macOS live), *Light*, or *Dark*. Text size is there too.

**Show site icons** (Appearance, on by default) puts each login's website icon in place of its type glyph, in the
lists and in the browser's *Fill login* picker; a site without an icon keeps the glyph. The icons come from your server's `/icons/<host>/icon.png`, as in the official clients, so the server learns which sites
you have logins for. A server set up with an external icon service (Vaultwarden's `ICON_SERVICE`) redirects there,
so that service learns the site names too; only https redirects to public hosts are followed, with no `Referer`.
Switch the setting off to keep your sites to yourself. Icons load only for the rows on screen, after scrolling or
typing pauses, and stay in memory only: the daemon keeps them until the vault locks, and nothing is written to disk.

Settings → Shortcuts → *Quick Panel hotkey* / *Generator hotkey* are shortcut recorders: click one,
it shows *Press a shortcut…*, then press the combination. It needs ⌘, ⌥ or ⌃ (⇧ can be added, but
not on its own) plus a letter, digit, Space, F1–F12, Return, Tab, an arrow or one of
`` ` \ [ ] , - . ' ; / = ``. It is saved at once and works system-wide straight away. Esc or
clicking elsewhere cancels; Delete or Backspace removes the Generator hotkey (the Quick Panel always
keeps one). The two can't be the same shortcut. Keys are recorded by their position on the
keyboard, as macOS matches global shortcuts, so ⌥ letters and non-Latin layouts record the key
itself. While a recorder waits, Vaultkeeper's own global hotkeys are off, so pressing the current
Quick Panel hotkey records it instead of opening the panel. They come back when recording ends,
when Settings closes, if the window process goes away, and in any case after 30 s. A combination
another app or macOS holds as a global shortcut still never reaches the recorder.

## Files

| Path | Content |
|---|---|
| `~/Library/Application Support/vaultkeeper/` | settings, encrypted vault cache per account, sockets (mode 0600) |
| `…/vaultkeeper/browsers.json`, `browser.sock` | browser pairings (public keys only) and the browser socket |
| login keychain, items prefixed `vaultkeeper` | refresh tokens |
| `~/Library/LaunchAgents/vaultkeeper.plist` | only with *Start at login* |
| `~/Library/Logs/vaultkeeper/daemon.log`, `ui.log`, `browser.log` | logs of the two processes, at most 1 MiB each plus one older `.1` file; not meant to hold secrets |

To uninstall:
1. Log out of each account in the app, then quit it.
2. `rm -rf /Applications/Vaultkeeper.app "$HOME/Library/Application Support/vaultkeeper" ~/Library/LaunchAgents/vaultkeeper.plist ~/Library/Logs/vaultkeeper`.

## Command line

```
vaultkeeper              start (or ask the running instance) and open the vault window
vaultkeeper --tray       menu bar only
vaultkeeper --search     open the Quick Panel, as its hotkey does (no vault window)
vaultkeeper --generator  open the password generator, as its hotkey does
vaultkeeper --mock       run on a built-in demo vault (master password: mock), touches no real data
```

## Development

```sh
scripts/check.sh                                     # fmt + clippy (also the pre-commit hook)
SLINT_BACKEND=winit-software cargo test --workspace  # unit + integration tests
scripts/e2e.sh                                       # e2e against docker Vaultwarden + Mailpit
```
