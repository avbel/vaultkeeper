# vaultkeeper UI design

The UI has two surfaces that share one vault core:

- **Quick Panel.** A Spotlight-like pop-up, opened with a global hotkey or a tray click.
  - It is search-first and shows 8 rows. Every row carries its own copy buttons.
  - This is where most daily use happens: find, copy, dismiss.
  - It hides when it loses focus or when Esc is pressed.
  - With an empty query it shows the 8 most recently used items.
- **Manager window.** Two panes: list | detail.
  - Filters are a row of dropdown chips above the list, not a permanent sidebar.
  - Used for editing, the generator, SSH keys, settings and browsing collections.
- **Status.** Sync and lock state sit in one footer cell, never in a banner.
- **Toasts.** They are small, non-modal and auto-dismissing, used for "Offline mode — showing cached vault" and errors.
  Copy feedback does not use toasts.

## Wireframes

**Manager window**
```
┌─────────────────────────────────────────────────────────────────────────┐
│ ⌕ Search vault…                                 [+ New ▾] [⚙] [🔒 Lock] │
│ [All ▾] [Type: Any ▾] [Folder: Any ▾] [Org: Personal ▾] [★ Favs]         │
├──────────────────────────────────────┬──────────────────────────────────┤
│ ● github.com    octocat   👤 🔑 ⏱ 482 913 ◔ │ GitHub                   ★  │
│ ○ AWS Console   admin@…   👤 🔑             │ Login · Work › Infra        │
│ ▤ Server runbook                      …    │ Username  octocat       [⎘] │
│ ▮ Visa ····4242 12/27     #  CVV           │ Password  ••••••••  [👁][⎘]  │
│ ⌂ Alice Smith             @  ☎             │ TOTP      482 913 ◔ 23s [⎘] │
│ ⚿ deploy-ed25519 exposed  pub 🔑           │ URI       https://github.com│
│                                            │ [Edit] [History] [Delete]   │
├──────────────────────────────────────┴──────────────────────────────────┤
│ Synced 2 min ago · 412 items · SSH agent: 2 keys            Clipboard 18s│
└─────────────────────────────────────────────────────────────────────────┘
```

**List row (Login), 36 px tall:** `icon | name | username (muted) | [copy user] [copy pass] | TOTP "482 913" + 12 px ring`
- **Copy buttons:** always visible, drawn at 55% opacity and at full opacity on row hover or focus. A click copies straight
  away, with no menu. After a click the button shows ✓ in the success colour for 1.2 s.
- **TOTP cell:** 6 digits in monospace, grouped `482 913`, next to an arc ring that drains clockwise. The ring turns the
  warning colour under 5 s. The row has no numeric countdown; that is in the detail pane. Codes are computed only for
  visible rows.
- **Buttons per type:**
  - Card: `#` (number) and `CVV`.
  - Identity: `@` (email) and `☎` (phone).
  - SSH key: `pub` (public key) and `🔑` (private key).
  - Note: a single `…` button that copies the notes.

**Quick Panel (560×~340)**
```
┌──────────────────────────────────────────────────────────┐
│ ⌕ gith|                                                   │
├──────────────────────────────────────────────────────────┤
│ ▸ ● github.com      octocat        👤  🔑  ⏱ 482 913 ◔   │
│   ● GitHub (work)   bot@corp       👤  🔑               │
├──────────────────────────────────────────────────────────┤
│ ↵ copy password  ⌘↵ TOTP  ⇧↵ username  ⌘O open  ⌘L lock   │
└──────────────────────────────────────────────────────────┘
```

**Lock screen:**
- It shows the server and the email.
- Below that: a master password field with a reveal toggle and the Unlock button.
- "Unlock with Touch ID" appears when enrolled.
- At the bottom: Log out and Settings.
- A wrong password shakes the field once and shows a red hint with the attempt count. No modal.

**Login:**
- Fields: server URL, email, master password.
- If the server asks for 2FA, a second step shows the provider picker (authenticator, email, recovery code), the code
  field and "Remember this device".
- New-device OTP step.

**SSH sign approval (always on top, 420 px):**
- It names the requesting process and pid, the key name and the SHA256 fingerprint.
- "Remember for this key until lock".
- Buttons: Deny (Esc) and Approve (↵). When "require Touch ID" is on, Approve triggers Touch ID.
- It auto-denies after 30 s, with a progress bar.

**Generator** (a slide-over in the detail pane, or standalone from the tray):
- A Password | Passphrase toggle, with the result in monospace and buttons [⎘] [↻].
- Password mode: length slider 5–128, A-Z, a-z, 0-9, `!@#$%^&*`, minimum numbers and minimum special.
- Passphrase mode: number of words, separator, capitalize, include number.
- "Avoid ambiguous" option and a history list.

**Settings:**
- Server.
- Theme: System / Light / Dark.
- Lock timeout: 1, 5, 15, 30 or 60 min, or "on sleep / screen lock".
- Clipboard clear: 10, 30 or 60 s, or never.
- "Start at login", "Ask to unlock on start", "Require master password on app start".
- Touch ID: enrol or remove.
- SSH agent on/off, with the socket path shown and copyable.
- "SSH requires approval": always, or remember until lock.
- "SSH requires Touch ID".
- Global hotkey.

**Tray menu:** Quick search, Open vault, Generator, Lock/Unlock, Sync now, Quit.

## Keyboard
- **Global:** ⌘⇧Space toggles the Quick Panel (configurable). ⌘⇧L locks.
- **List and Quick Panel:**
  - Moving and searching: ↑↓ move; typing always goes to search.
  - Copying: ↵ password · ⇧↵ username · ⌘↵ TOTP.
  - Item actions: ⌘⇧↵ auto-type in the Quick Panel (username, Tab, password into the app
    behind it), open URI in the Manager · ⌘O open in Manager · ⌘E edit · ⌘F favorite.
  - App actions: ⌘N new · ⌘G generator · ⌘, settings.
  - Filters and dismissing: ⌘1…5 filter by type · Esc clears search, then closes the panel.
- **Detail:** Tab moves through fields; ⌘C copies the focused field.

## Visual tokens

| token | light | dark |
|---|---|---|
| bg | #F6F7F9 | #141518 |
| surface | #FFFFFF | #1C1E23 |
| surface-raised | #EEF0F3 | #24272E |
| border | #D9DCE2 | #2F333B |
| text | #1A1D23 | #E6E8EC |
| text-muted | #6B7280 | #8B919C |
| accent | #2563EB | #6FA3FF |
| accent-fg | #FFFFFF | #0B1220 |
| success | #16A34A | #4ADE80 |
| warn | #D97706 | #FBBF24 |
| danger | #DC2626 | #F87171 |
| focus ring | accent, 2 px | accent, 2 px |

- **Theme:** follows the system by default, with System / Light / Dark in settings. Switching swaps one token struct;
  widgets have no colours of their own.
- **Type:** the system UI font at 11 (meta), 13 (body and rows), 15 (detail title) and 20 (lock screen). Monospace at 13
  only for passwords, TOTP, fingerprints and card numbers.
- **Spacing and shape:** 4 px grid; rows 36 px; panel padding 12; gap between fields 8. Radius 6 for controls, 10 for
  pop-ups, 0 for the list. No shadows except on the Quick Panel and the SSH prompt.
- **Icons:** one monochrome 16 px stroke set. Type glyphs: ● login, ▤ note, ▮ card, ⌂ identity, ⚿ SSH. No favicons.
- **Copy feedback:** the button shows ✓, and the footer reads "Copied password · clears in 30s" with a 2 px drain bar.
  No toast windows and no system notifications for copies.

## Deliberately not copied from Bitwarden
- The permanent filters sidebar.
- Copy actions hidden in ⋮ menus.
- TOTP only in the detail view.
- "Vault unlocked" and sync banners.
- Modal confirmations for routine actions; confirmation is inline instead, e.g. `Delete? [Yes][No]`.
- Favicons.
- Send, Reports and upsell tabs.

## Change: sidebar with folder management (user request)
The Manager window has a collapsible left sidebar like the official app, about 200 px wide and toggled with ⌘\. It
replaces the filter chips.

Sections, top to bottom:
- All items, Favorites.
- Types, each with a count.
- Folders: "No folder" plus every folder, with counts.
- Collections, grouped by organization.
- Trash.

Folder management:
- "+" on the Folders header adds a folder inline.
- The ⋯ menu or a right-click on a folder row offers Rename (inline) and Delete (inline confirm; items move to
  "No folder").
- Items move to a folder from the item detail or edit form, or by drag-and-drop where Slint supports it.
