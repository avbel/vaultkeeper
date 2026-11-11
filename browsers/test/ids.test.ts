import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { createHash } from "node:crypto";
import { describe, expect, it } from "vite-plus/test";
import { CHROME_EXTENSION_ID, FIREFOX_EXTENSION_ID } from "../src/shared/ids.ts";

const RUST = resolve(import.meta.dirname, "../../app/src/daemon/browser/ids.rs");

function rustConst(source: string, name: string): string | undefined {
  return new RegExp(`pub const ${name}: &str = "([^"]*)";`).exec(source)?.[1];
}

describe("extension ids", () => {
  const rust = readFileSync(RUST, "utf8");

  it("match the Rust constants", () => {
    expect(rustConst(rust, "CHROME_EXTENSION_ID")).toBe(CHROME_EXTENSION_ID);
    expect(rustConst(rust, "FIREFOX_EXTENSION_ID")).toBe(FIREFOX_EXTENSION_ID);
  });

  it("chrome id is derived from the manifest key", () => {
    const manifest = JSON.parse(
      readFileSync(resolve(import.meta.dirname, "../manifest.chrome.json"), "utf8"),
    ) as { key: string };
    const hex = createHash("sha256")
      .update(Buffer.from(manifest.key, "base64"))
      .digest("hex")
      .slice(0, 32);
    const id = hex
      .split("")
      .map((c) => String.fromCharCode("a".charCodeAt(0) + parseInt(c, 16)))
      .join("");
    expect(id).toBe(CHROME_EXTENSION_ID);
  });

  it("firefox manifest uses the same gecko id", () => {
    const manifest = JSON.parse(
      readFileSync(resolve(import.meta.dirname, "../manifest.firefox.json"), "utf8"),
    ) as { browser_specific_settings: { gecko: { id: string } } };
    expect(manifest.browser_specific_settings.gecko.id).toBe(FIREFOX_EXTENSION_ID);
  });
});
