// @vitest-environment jsdom
import { beforeEach, describe, expect, test, vi } from "vite-plus/test";
import { beginFill } from "../src/content/begin.ts";
import { createFiller } from "../src/content/fill.ts";
import type { ToBackground } from "../src/shared/messages.ts";
import { detect, input, render, visible } from "./content-dom.ts";

function run(html: string, choose = false, active: Element | null = null) {
  render(html);
  const sent: ToBackground[] = [];
  const toast = vi.fn();
  const filler = createFiller({ send: (m) => sent.push(m), isVisible: visible });
  const found = beginFill({ rescan: detect, active: () => active, filler, toast }, choose);
  return { found, sent, toast, filler };
}

beforeEach(() => {
  document.body.innerHTML = "";
});

describe("beginFill", () => {
  test("Google-style identifier step starts a username-only request", () => {
    const { found, sent, toast } = run(
      `<div><input type="email" id="identifierId" name="identifier" autocomplete="username"><div role="button">Next</div></div>`,
      true,
    );
    expect(found).toBe(true);
    expect(sent[0]).toMatchObject({
      kind: "fill_request",
      choose: true,
      fields: { username: true, password: false },
    });
    expect(toast).not.toHaveBeenCalled();
  });

  test("password step starts a password-only request", () => {
    const { found, sent } = run(
      `<div><input type="password" name="Passwd"><div role="button">Next</div></div>`,
    );
    expect(found).toBe(true);
    expect(sent[0]).toMatchObject({ fields: { username: false, password: true } });
  });

  test("a page with no form is not found and shows a toast", () => {
    const { found, sent, toast } = run(`<p>Hello</p><input type="checkbox">`);
    expect(found).toBe(false);
    expect(sent).toEqual([]);
    expect(toast).toHaveBeenCalledWith("No login form found on this page");
  });

  test("the focused form wins over the first one", () => {
    render(
      `<form id="a"><input id="ua" type="text"><input type="password"></form><form id="b"><input id="ub" type="text"><input type="password"></form>`,
    );
    const sent: ToBackground[] = [];
    const filler = createFiller({ send: (m) => sent.push(m), isVisible: visible });
    const found = beginFill(
      { rescan: detect, active: () => input("#ub"), filler, toast: vi.fn() },
      false,
    );
    expect(found).toBe(true);
    expect(sent).toHaveLength(1);
  });

  test("a second begin while a fill is in flight still reports found", () => {
    const { filler, toast } = run(`<form><input type="text"><input type="password"></form>`);
    const again = beginFill({ rescan: detect, active: () => null, filler, toast }, false);
    expect(again).toBe(true);
    expect(toast).not.toHaveBeenCalled();
  });

  test("a signup-only page has nothing to fill", () => {
    const { found, toast } = run(`<form><input type="password"><input type="password"></form>`);
    expect(found).toBe(false);
    expect(toast).toHaveBeenCalled();
  });
});
