import { readFileSync } from "node:fs";
import { describe, expect, it } from "vite-plus/test";
import { CSS_PATH, SLINT_PATH, generateCss, parseTokens } from "../scripts/gen-theme.mjs";

describe("theme generator", () => {
  it("committed theme.css matches the generator output", () => {
    const generated = generateCss(readFileSync(SLINT_PATH, "utf8"));
    expect(readFileSync(CSS_PATH, "utf8")).toBe(generated);
  });

  it("parses light and dark values from a slint line", () => {
    const tokens = parseTokens(
      "    out property <color> surface-raised: dark ? #262930 : #EEF0F3;\n" +
        "    out property <color> hover: text.with-alpha(dark ? 0.07 : 0.05);\n",
    );
    expect(tokens).toEqual([{ name: "surface-raised", dark: "#262930", light: "#EEF0F3" }]);
  });

  it("emits the three selector blocks", () => {
    const css = generateCss("out property <color> bg: dark ? #141518 : #F6F7F9;");
    expect(css).toContain(":root {\n  --bg: #F6F7F9;");
    expect(css).toContain(':root[data-theme="dark"] {\n  --bg: #141518;');
    expect(css).toContain(':root:not([data-theme="light"]) {\n    --bg: #141518;');
  });

  it("fails when the slint file has no tokens", () => {
    expect(() => generateCss("nothing here")).toThrow();
  });
});
