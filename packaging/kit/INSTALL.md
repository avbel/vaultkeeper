# Vaultkeeper — installation (Mac with Apple silicon)

Vaultkeeper is a password manager that works with a Vaultwarden/Bitwarden server. It lives in the menu bar. The Chrome
extension fills passwords on websites. The app is not notarized by Apple, which is why a few extra clicks are needed.

You need: a Mac with an M1 or newer chip, macOS 13 or newer, Google Chrome, and the server address, email and master
password.

## 1. Unpack the kit

Copy the zip to the Mac with **AirDrop or a USB stick** (a download through a browser or messenger also works, see
"If macOS blocks it" below). Double-click the zip to unpack it. You get a folder `Vaultkeeper-kit` with:

- `Vaultkeeper.app` — the app
- `chrome-extension/` — the Chrome extension
- `vaultkeeper-firefox.xpi` — the Firefox add-on
- `install.command` — the installer
- `INSTALL.md` — this guide

## 2. Install the app (one double-click)

Double-click `install.command`. A Terminal window opens and shows four steps; when it prints "Done" you can close it.
Vaultkeeper is now in Applications and its icon appears in the menu bar at the top right.

Manual alternative: drag `Vaultkeeper.app` into Applications, then open Terminal and run
`xattr -dr com.apple.quarantine /Applications/Vaultkeeper.app`, then open the app. Also copy the `chrome-extension` folder
to a place that stays, e.g. `~/Library/Application Support/Vaultkeeper/chrome-extension`.

### If macOS blocks it

- *"install.command can't be opened"* — right-click the file → **Open** → **Open**. Or in Terminal:
  `bash ~/Downloads/Vaultkeeper-kit/install.command` (adjust the folder).
- *"Vaultkeeper can't be opened because Apple cannot check it"* — System Settings → **Privacy & Security**, scroll down,
  click **Open Anyway** next to Vaultkeeper, confirm with the password or Touch ID. The installer normally prevents this.

## 3. Sign in

Click the Vaultkeeper icon in the menu bar → open the vault window. Enter the server URL, email and master password.
Optionally turn on Touch ID in Settings.

## 4. Connect Chrome

1. In Vaultkeeper: **Settings → Browsers** → turn on **Browser integration** and keep **Install for Chrome** on.
2. In Chrome open `chrome://extensions`, turn on **Developer mode** (top right), click **Load unpacked** and choose the
   folder `~/Library/Application Support/Vaultkeeper/chrome-extension` (the installer opens it in Finder; in the file
   dialog press ⌘⇧G and paste the path). Do not delete or move this folder afterwards.
3. Pin the extension: puzzle-piece icon in Chrome → pin Vaultkeeper.
4. Click the extension icon. A window **Connect Chrome?** appears with a code. Check it is the same code as in the
   extension popup, then click **Connect**. (Return does not approve on purpose.)

Chrome may show "Disable developer mode extensions" on start. Choose to keep the extension; it is normal for an extension
loaded from a folder.

## 4b. Connect Firefox

1. In Vaultkeeper: **Settings → Browsers** → turn on **Install for Firefox**.
2. Drag `vaultkeeper-firefox.xpi` onto a Firefox window and click **Add**. It is signed by Mozilla, so no developer
   setting is needed.
3. Click the extension icon and approve the **Connect Firefox?** window the same way as for Chrome.

## 5. Daily use

- Fill a login: click the Vaultkeeper icon in the password field, press **⌘⇧L**, or use the extension popup → *Fill this
  page*. Pick the login with the arrows and Return.
- After signing in on a new site, a *Save login?* window appears in the top-right corner. Answer it with the mouse.
- Quick search of all logins from anywhere: the Quick Panel hotkey (see Settings).
- Start at login: Settings → turn on *Start at login*.

## Updating

Unpack the new kit and run `install.command` again; the settings and the vault are kept. Then press the reload button
for Vaultkeeper in `chrome://extensions`. In Firefox drag the new `vaultkeeper-firefox.xpi` onto a window again.

## Uninstall

Run `uninstall.command` (it is also in the kit), then remove the extension in `chrome://extensions`. Logins are only
copies of what is on the server; nothing on the server is deleted.
