// Renders the app icon (packaging/macos/icon.svg: blue shield on a rounded tile) to src/ui/icons/icon-<size>.png.
// PNG is required: Chrome does not accept SVG for manifest icons.
// Needs `rsvg-convert` (brew install librsvg); the PNGs are committed, so this only runs when the app icon changes.
// 48 and 128 px show the whole tile; 16 and 32 px drop the tile and crop to the shield so it stays legible.
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const outDir = resolve(here, "../src/ui/icons");
const source = readFileSync(resolve(here, "../../packaging/macos/icon.svg"), "utf8");

const FULL_VIEWBOX = 'viewBox="0 0 1024 1024"';
const TILE_ONLY = { viewBox: "100 100 824 824", dropTile: false };
const SHIELD_ONLY = { viewBox: "212 222 600 600", dropTile: true };
const VARIANTS = [
  { size: 16, ...SHIELD_ONLY },
  { size: 32, ...SHIELD_ONLY },
  { size: 48, ...TILE_ONLY },
  { size: 128, ...TILE_ONLY },
];

function variantSvg({ viewBox, dropTile }) {
  if (!source.includes(FULL_VIEWBOX)) {
    throw new Error("icon.svg no longer has the expected viewBox");
  }
  let svg = source.replace(FULL_VIEWBOX, `viewBox="${viewBox}"`);
  if (dropTile) {
    const lines = svg.split("\n");
    const kept = lines.filter((line) => !line.includes('fill="url(#bg)"'));
    if (kept.length === lines.length) {
      throw new Error("icon.svg tile rect not found");
    }
    svg = kept.join("\n");
  }
  return svg;
}

mkdirSync(outDir, { recursive: true });
for (const variant of VARIANTS) {
  const png = execFileSync(
    "rsvg-convert",
    ["-w", String(variant.size), "-h", String(variant.size)],
    {
      input: variantSvg(variant),
      maxBuffer: 1 << 24,
    },
  );
  writeFileSync(resolve(outDir, `icon-${variant.size}.png`), png);
}
console.log(`wrote ${VARIANTS.length} icons to ${outDir}`);
