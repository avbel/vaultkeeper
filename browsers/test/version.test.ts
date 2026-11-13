import { readFileSync } from "node:fs";
import { describe, expect, it } from "vite-plus/test";
import { mergeManifest, workspaceVersion } from "../scripts/build.mjs";

describe("workspaceVersion", () => {
  it("reads [workspace.package] and ignores versions in other sections", () => {
    const toml = [
      "[workspace]",
      'members = ["app"]',
      "",
      "[workspace.package]",
      'version = "1.2.3"',
      'edition = "2024"',
      "",
      "[workspace.dependencies]",
      'serde = { version = "1.0.0" }',
    ].join("\n");
    expect(workspaceVersion(toml)).toBe("1.2.3");
  });

  it("fails without a workspace version", () => {
    expect(() => workspaceVersion('[package]\nversion = "1.0.0"\n')).toThrow(/workspace\.package/);
  });

  it("finds the repository's version", () => {
    expect(workspaceVersion(readFileSync("../Cargo.toml", "utf8"))).toMatch(/^\d+\.\d+\.\d+$/);
  });
});

it("the manifest takes the workspace version", () => {
  expect(mergeManifest({ name: "x" }, { key: "k" }, "1.2.3")).toEqual({
    name: "x",
    key: "k",
    version: "1.2.3",
  });
});
