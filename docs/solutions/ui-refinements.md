# vaultkeeper UI refinements (modern and comfortable)

This comes from a design consult (Fable, medium effort) and takes priority over `ui-design.md` wherever the two conflict.

**RAM rules:**
- All motion is driven by properties (`animate` / `states`), so at rest it renders 0 frames.
- `Spinner` (which uses `animation-tick()`) must always sit behind `if busy:`.
- The TOTP ring drains in one step per second; it is never interpolated.

## Hierarchy and density
- **Spacing tokens:** s1 4 · s2 8 · s3 12 · s4 16 · s5 24 · s6 32. Don't use ad-hoc 6/10/14 values.
- **Sidebar:** 216 px wide (min 180).
- **List pane:** min 320, stretch 3. **Detail pane:** min 380, stretch 2.
- **Manager window:** default 1120×700, min 760×480.
- **Rows:** 40 px in the Manager, 36 px in the Quick Panel. Use `Theme.row-height` and `row-height-compact`.

**Type:**

| role | size/weight | tracking |
|---|---|---|
| meta and section labels | 11/600 | 0.4 px, uppercase for section labels only |
| subtitle and hints | 12/400 | 0 |
| row name | 13/500 | 0 |
| body | 13/400 | 0 |
| detail title | 17/600 | -0.2 px |
| lock and login title | 22/600 | -0.3 px |
| mono | 13/500, or 15 for the detail TOTP | 1 px |

**Columns:** name and subtitle get `preferred-width: 0`, with stretch 3 and 2, so the column edges stay at fixed x positions. ★ is a 10 px glyph at 0.8 opacity after the name.

**Row and sidebar states:**
- **Hover:** text @0.05 (light) / @0.07 (dark), with a 100 ms ease-out background transition.
- **Selected:** accent @0.12 / @0.20, plus a 2 px accent bar at x=0.
- **Selected and hovered:** accent @0.16 / @0.26.
- **Keyboard focus:** a 2 px inner accent ring, shown only while the list has keyboard focus.
- **Sidebar item:** 28 px tall, radius 6, inset 8.

## Colour tokens (added to the existing table)

| token | light | dark |
|---|---|---|
| surface-raised | #EEF0F3 | #262930 |
| surface-popup | #FFFFFF | #2A2D35 |
| border | #D9DCE2 | #30343C |
| border-subtle | text @0.08 | text @0.08 |
| text-muted | #5F6675 | #969CA7 |
| success-text | #15803D | #4ADE80 |
| warn-text | #B45309 | #FBBF24 |
| shadow (popups only) | #000 @0.14, blur 16, y 4 | #000 @0.45, blur 20, y 6 |

- **Danger text:** #DC2626 for text of 12 px and up; #B91C1C at 11 px.
- **Elevation:** pop-ups use surface-popup + a 1 px border + the shadow. Nothing else casts a shadow, and nothing builds colours with `.darker()` chains.

**Kind palette** (foreground light / dark; the chip background is fg @0.14 light, @0.22 dark):

| kind | light | dark |
|---|---|---|
| login | #2563EB | #6FA3FF |
| note | #B45309 | #FBBF24 |
| card | #7C3AED | #B795FF |
| identity | #0F766E | #2DD4BF |
| SSH key | #15803D | #4ADE80 |
| other | text-muted | text-muted |

**Kind chips:** 22×22 with radius 6 in rows, 14×14 with radius 4 in the sidebar, 28×28 in the detail header. The accent colour is reserved for selection, focus, the primary button, links and the TOTP ring.

## Micro-interactions

| what | how | timing |
|---|---|---|
| copy → ✓ | both glyphs stay instantiated and crossfade; ✓ slides up 3 px→0; background success @0.14 | in 120 ms ease-out, out 200 ms ease-in, background 400 ms; ✓ shown 1.2 s |
| TOTP ring | 14 px ring with a 2 px stroke; track is border-subtle; drains in steps; turns warn under 5 s and the digits turn warn-text | colour change 300 ms |
| Quick Panel | the window shows at once; the inner root fades opacity 0→1 while y goes -6→0 | 160 ms `cubic-bezier(0.2,0,0,1)`; hides instantly |
| row hover | copy buttons go from 0.55 to 1 opacity; kind chip from 0.85 to 1 | 100 ms |
| toast | 36 px tall; opacity plus y +8→0; `visible: opacity > 0`; hovering pauses the 4 s timer | in 180 ms, out 220 ms |
| inline confirm | `Delete? [Yes(danger-filled)][No]`; Esc cancels; auto-cancels after 6 s; background danger @0.06 | 120 ms |
| sidebar collapse | width 216→36 (a rail holding just the toggle) with clip; content opacity →0 | width 220 ms ease-in-out-quart, opacity 120 ms |
| wrong password | decaying shake: +8, -8, +5, -5, +2, 0, with `animate x` 45 ms per step; border turns danger for 1.2 s | ≈270 ms |

## Comfort
- **Shortcut hints:**
  - Every action with a shortcut shows it as an 11 px muted suffix (`New ⌘N`).
  - The Quick Panel footer shows key caps: surface-raised, radius 4, mono 11.
  - Shortcuts: ⌘1…5 filter by type · ⌘\ toggles the sidebar · ⌘F focuses search · ⌘K opens the Quick Panel in-app.
  - Tab order: search → list → detail.
- **Empty states:** a centred block with a 24 px muted icon, a 13/500 title, a 12 px muted body and an optional button.
  - No items: "No items yet · Add your first login · [+ New ⌘N]".
  - No search results: "No results for "…" · [Clear filters]".
  - Offline: the footer reads `⚠ Offline · showing cached vault` in warn-text, alongside the offline toast.
  - Locked Quick Panel: an inline master password field (plus Touch ID).
- **Skeletons instead of spinners:**
  - Loads over 300 ms show 3 static skeleton rows at text @0.08, with no shimmer.
  - Spinners appear only inline, next to a verb ("Saving…").
- **Errors:** written as "what happened · what to do", in 12 px danger text under the field, with the field border in danger. No modals.
- **Login:**
  - The server field comes first, with suggestions from servers already used.
  - After URL validation a green "Reachable" line appears.
  - The primary button is full width (360 px).
  - After login: a skeleton list and "Syncing…" in the footer.
- **Large text:** `Theme.scale` (1.0, 1.15 or 1.3) multiplies every font and the row heights. Use `min-height` wherever text can scale.
- **Window:** the Manager remembers x, y, w, h and the sidebar-collapsed state, clamped to the screen. The Quick Panel is centred on the cursor's screen with its top at 22% of the screen height.
- **macOS:**
  - The title bar is transparent with full-size content, and the header has a 78 px left inset for the traffic lights.
  - ⌘W hides to the tray, ⌘Q quits, ⌘, opens settings.
  - Esc first clears the search, then closes the panel.
  - ↩ in the list copies the password.
  - Hints always use ⌘ glyphs, never "Ctrl".

## Components
- **Detail field row:** 32 px; label column 96 px, muted, 12/500; then the value; then 28 px reveal and copy buttons; gap 8.
- **Sidebar count badge:** 11/500 in a pill that is 18 px tall with 6 px padding, surface-raised background; accent @0.18 when the item is selected.
- **Search field:**
  - Manager: 32 px tall, radius 6, a muted 16 px icon and a `⌘F` cap.
  - Quick Panel: 44 px tall, 15 px text, an `Esc` cap.
- **Buttons:** 28 px tall, radius 6, 10 px horizontal padding, 13/500 text.
  - Primary: accent background with accent-fg text.
  - Secondary: surface-raised background with a 1 px border.
  - Ghost: transparent background.
  - Danger: 1 px border in danger @0.4 with danger text; hover fills danger @0.08.
  - Disabled: opacity 0.45.
  - Focus ring: 2 px, accent @0.4, drawn outside the button.
- **Text input:** 32 px; 1 px border; on focus a 2 px accent outer ring with no change in size; invalid shows a 1 px danger border plus a 12 px message.
- **Toggle (settings):** a 36×20 track with radius 10; a 16 px knob that slides x 2→18 in 160 ms ease-out.
- **Toast:** 36 px, radius 10, surface-popup, with a border and a shadow; a 6 px dot, optionally a ghost action ("Retry"); placed 40 px from the bottom.
- **Account switcher:**
  - Control: 32 px with a 24 px avatar, coloured from a hash of the email; email 13/500, then the host 11 muted.
  - Pop-up: 260 px wide with 32 px rows; ✓ marks the active account; Add account / Lock / Log out (in danger) with their ⌘ hints.
- **Quick Panel:** 560 wide, radius 12, border and shadow. Search 44 px tall, then 8 rows of 36 px, then a 28 px footer with key caps.

## Do / don't
- **Do:**
  - one accent colour, with colour by kind for everything else;
  - animate only opacity, y, width and background;
  - keep `if busy:` around every spinner;
  - persist the window geometry;
  - show a hint next to every action that has a shortcut;
  - use `min-height`.
- **Don't:**
  - build colours with `.darker()` chains;
  - snap `visible` on and off for the toast or the sidebar;
  - animate the TOTP drain continuously;
  - use shadows as the elevation cue in dark mode;
  - use modal confirms;
  - put 11 px text in the warn or success icon colours.

## Top 10 by impact
1. Kind chips.
2. Fixed proportional row columns.
3. 40 px Manager rows with 13/500 names.
4. Animated sidebar collapse to a rail.
5. Toast and Quick Panel fade in and slide.
6. Selected-row bar and a keyboard focus ring.
7. Contrast tokens.
8. Full-size-content title bar plus ⌘ hints.
9. Empty states and skeletons.
10. Copy ✓ crossfade and the decaying shake.
