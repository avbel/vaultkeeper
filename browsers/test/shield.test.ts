import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vite-plus/test";
import { SHIELD_PATH } from "../src/shared/shield.ts";

const ROOT = resolve(import.meta.dirname, "..");

function pathOf(file: string): string | undefined {
  return /\sd="([^"]*)"/.exec(readFileSync(resolve(ROOT, file), "utf8"))?.[1];
}

describe("shield glyph", () => {
  it("popup svg and in-page path match the app's tray icon", () => {
    const tray = pathOf("../app/ui/icons/tray-dark.svg");
    expect(tray).toBeTruthy();
    expect(pathOf("src/ui/icons/shield.svg")).toBe(tray);
    expect(SHIELD_PATH).toBe(tray);
  });
});
