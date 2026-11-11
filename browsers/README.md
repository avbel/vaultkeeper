# Vaultkeeper browser extension

Thin client for the Vaultkeeper app (Chrome and Firefox, Manifest V3). It never holds the vault, the master password or a
list of logins; see `../BROWSERS.md` for the design, wire protocol and security model.

Layout: `src/background` (native messaging, pairing, router), `src/content` (page detection and fill), `src/ui` (popup,
theme), `src/shared`, `manifest.*.json`, `scripts/`, `test/`.

## Tooling

pnpm, Vite+ (`vite-plus` 1.5.1: build, `vp test`, `vp check`) and TypeScript 7.0.2, plus `jsdom` and `web-ext`. No
runtime dependencies. Tested together: `vp check`, `vp test` and `tsc --noEmit` all work with TypeScript 7, so no fallback
to vitest/TypeScript 6 was needed. `pnpm peers check` warns about an unmet `vite` peer for vitest; that is Vite+'s own
`vite` alias and the build and tests run fine.

```sh
pnpm install
pnpm run build              # dist/chrome and dist/firefox
pnpm exec vp check          # format, lint, type-aware lint
pnpm exec vp test           # vp test is non-watch by default
pnpm exec tsc --noEmit
pnpm run gen-theme          # regenerate src/ui/theme.css from ../app/ui/theme.slint
node scripts/gen-icons.mjs  # regenerate the PNG icons
```

`src/ui/theme.css` is generated and committed; `test/theme.test.ts` fails when `app/ui/theme.slint` changed and the CSS
was not regenerated. Hand-written tokens (alphas, sizes, fonts) live in `scripts/gen-theme.mjs`.

## Extension ids

`src/shared/ids.ts` and `app/src/daemon/browser/ids.rs` hold the same two constants; `test/ids.test.ts` compares them and
checks that the Chrome id is the one derived from the `key` in `manifest.chrome.json`.

The Chrome `key` (public key) is committed so every build has the same id. The matching **private key is not in the
repository**: it is `~/.vaultkeeper-secrets/chrome-extension-key.pem` on the machine that generated it. Keep it if the
extension is ever packed as a `.crx` or uploaded to the Chrome Web Store (which wants its own key and changes the id; then
regenerate both constants). To make a new key: `openssl genrsa 2048`, put the base64 DER public key in the manifest, and
derive the id as the first 32 hex characters of the SHA-256 of that DER with `0-9a-f` mapped to `a-p`.

## Load unpacked

Chrome: `chrome://extensions` → Developer mode → Load unpacked → `dist/chrome`. Branded Chrome ignores
`--load-extension`, so this is manual.

Firefox: `pnpm run run:firefox` (web-ext with the installed Firefox) or `about:debugging` → This Firefox → Load Temporary
Add-on → `dist/firefox/manifest.json`.

The app side must be set up first: enable browser integration in Vaultkeeper settings so the native messaging manifest for
the browser is installed.

## Sign (Firefox)

```sh
pnpm run build
WEB_EXT_API_KEY=... WEB_EXT_API_SECRET=... pnpm run sign:firefox   # unlisted channel on AMO
```

Chrome distribution (Web Store or enterprise policy) is an open decision in `BROWSERS.md` section 12.

`web-ext lint` warns that `data_collection_permissions` is unsupported below Firefox 140; older versions ignore the key
and AMO requires it for new add-ons, so it stays.
