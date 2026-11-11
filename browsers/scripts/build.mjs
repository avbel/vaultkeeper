import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "vite-plus";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const TARGETS = ["chrome", "firefox"];

// Content scripts are classic scripts (IIFE); the background and popup are ES modules.
const ENTRIES = [
  { entry: "src/background/index.ts", file: "background.js", format: "es" },
  { entry: "src/content/index.ts", file: "content.js", format: "iife", optional: true },
  { entry: "src/ui/popup.ts", file: "popup.js", format: "es" },
];

const STATIC_FILES = ["popup.html", "popup.css", "theme.css"];

function readJson(name) {
  return JSON.parse(readFileSync(resolve(root, name), "utf8"));
}

export function mergeManifest(base, target) {
  return { ...base, ...target };
}

async function bundle(outDir, spec) {
  await build({
    root,
    configFile: false,
    publicDir: false,
    logLevel: "warn",
    build: {
      outDir,
      emptyOutDir: false,
      minify: false,
      sourcemap: false,
      target: "es2023",
      lib: {
        entry: resolve(root, spec.entry),
        formats: [spec.format],
        name: "vaultkeeper",
        fileName: () => spec.file,
      },
    },
  });
}

async function buildTarget(target) {
  const outDir = resolve(root, "dist", target);
  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });

  const manifest = mergeManifest(
    readJson("manifest.base.json"),
    readJson(`manifest.${target}.json`),
  );
  for (const spec of ENTRIES) {
    if (spec.optional && !existsSync(resolve(root, spec.entry))) {
      console.warn(`skipping ${spec.entry}: not found, dropping content_scripts from the manifest`);
      delete manifest.content_scripts;
      continue;
    }
    await bundle(outDir, spec);
  }
  for (const file of STATIC_FILES) {
    cpSync(resolve(root, "src/ui", file), resolve(outDir, file));
  }
  cpSync(resolve(root, "src/ui/icons"), resolve(outDir, "icons"), { recursive: true });
  writeFileSync(resolve(outDir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`built dist/${target}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  for (const target of TARGETS) {
    await buildTarget(target);
  }
}
