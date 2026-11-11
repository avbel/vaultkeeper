// Draws the extension icon (the app's key glyph on an accent tile) into src/ui/icons/icon-<size>.png.
// PNG is required: Chrome does not accept SVG for manifest icons.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { crc32, deflateSync } from "node:zlib";

const here = dirname(fileURLToPath(import.meta.url));
const outDir = resolve(here, "../src/ui/icons");
const SIZES = [16, 32, 48, 128];
const SS = 4;

const css = readFileSync(resolve(here, "../src/ui/theme.css"), "utf8");
const accent = /--accent: #([0-9A-F]{6});/.exec(css)?.[1] ?? "2563EB";
const tile = [0, 2, 4].map((i) => parseInt(accent.slice(i, i + 2), 16));

const STROKE_HALF = 0.75;
const SEGMENTS = [
  [7.8, 8, 14, 8],
  [12, 8, 12, 10.5],
  [14, 8, 14, 10],
];

function segmentDistance(px, py, [x1, y1, x2, y2]) {
  const dx = x2 - x1;
  const dy = y2 - y1;
  const t = Math.max(0, Math.min(1, ((px - x1) * dx + (py - y1) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(px - (x1 + t * dx), py - (y1 + t * dy));
}

function inGlyph(x, y) {
  const gx = (x - 8) / 0.78 + 8.5;
  const gy = (y - 8) / 0.78 + 8;
  if (Math.abs(Math.hypot(gx - 5, gy - 8) - 2.8) <= STROKE_HALF) {
    return true;
  }
  return SEGMENTS.some((s) => segmentDistance(gx, gy, s) <= STROKE_HALF);
}

function inTile(x, y) {
  const r = 3.5;
  const cx = Math.max(r, Math.min(16 - r, x));
  const cy = Math.max(r, Math.min(16 - r, y));
  return Math.hypot(x - cx, y - cy) <= r;
}

function render(size) {
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let py = 0; py < size; py++) {
    raw[py * (size * 4 + 1)] = 0;
    for (let px = 0; px < size; px++) {
      let tileHits = 0;
      let glyphHits = 0;
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const x = ((px + (sx + 0.5) / SS) / size) * 16;
          const y = ((py + (sy + 0.5) / SS) / size) * 16;
          if (inTile(x, y)) {
            tileHits++;
            if (inGlyph(x, y)) {
              glyphHits++;
            }
          }
        }
      }
      const total = SS * SS;
      const glyphShare = tileHits ? glyphHits / tileHits : 0;
      const o = py * (size * 4 + 1) + 1 + px * 4;
      for (let c = 0; c < 3; c++) {
        raw[o + c] = Math.round(tile[c] * (1 - glyphShare) + 255 * glyphShare);
      }
      raw[o + 3] = Math.round((tileHits / total) * 255);
    }
  }
  return raw;
}

function chunk(type, data) {
  const head = Buffer.alloc(8);
  head.writeUInt32BE(data.length, 0);
  head.write(type, 4, "ascii");
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([head.subarray(4), data])), 0);
  return Buffer.concat([head, data, crc]);
}

function png(size) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(render(size))),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

mkdirSync(outDir, { recursive: true });
for (const size of SIZES) {
  writeFileSync(resolve(outDir, `icon-${size}.png`), png(size));
}
console.log(`wrote ${SIZES.length} icons to ${outDir}`);
