// @vitest-environment jsdom
import { beforeEach, describe, expect, test, vi } from "vite-plus/test";
import { createAutofill, type AutofillDeps } from "../src/content/autofill.ts";
import { createFiller } from "../src/content/fill.ts";
import type { ToBackground } from "../src/shared/messages.ts";
import { detect, input, render, visible } from "./content-dom.ts";

const LOGIN = `<form><input id="u" type="text"><input id="p" type="password"></form>`;

function setup(overrides: Partial<AutofillDeps> = {}) {
  const sent: ToBackground[] = [];
  const filler = createFiller({ send: (m) => sent.push(m), isVisible: visible });
  const autofill = createAutofill({
    filler,
    isTopFrame: () => true,
    protocol: () => "https:",
    isShown: () => true,
    ...overrides,
  });
  return { autofill, sent };
}

beforeEach(() => {
  document.body.innerHTML = "";
});

describe("automatic fill trigger", () => {
  test("asks once for a visible, empty login form on an https top frame", () => {
    render(LOGIN);
    const { autofill, sent } = setup();
    expect(autofill.attempt(detect())).toBe(true);
    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({
      kind: "fill_request",
      auto: true,
      choose: false,
      fields: { username: true, password: true },
    });
    expect(autofill.attempt(detect())).toBe(false);
    expect(sent).toHaveLength(1);
  });

  test("leaves a form with a typed password alone, and tries again once it is empty", () => {
    render(LOGIN);
    input("#p").value = "typed";
    const { autofill, sent } = setup();
    expect(autofill.attempt(detect())).toBe(false);
    expect(sent).toEqual([]);
    input("#p").value = "";
    expect(autofill.attempt(detect())).toBe(true);
  });

  test("does not overwrite a typed username but still asks for the password", () => {
    render(LOGIN);
    input("#u").value = "me";
    const { autofill, sent } = setup();
    expect(autofill.attempt(detect())).toBe(true);
    expect(sent[0]).toMatchObject({ fields: { username: false, password: true } });
  });

  test("never asks from a frame, on http, or in a background tab", () => {
    render(LOGIN);
    const forms = detect();
    for (const overrides of [
      { isTopFrame: () => false },
      { protocol: () => "http:" },
      { isShown: () => false },
    ]) {
      const { autofill, sent } = setup(overrides);
      expect(autofill.attempt(forms)).toBe(false);
      expect(sent).toEqual([]);
    }
  });

  test("a page opened in the background is filled once it is shown", () => {
    render(LOGIN);
    let shown = false;
    const { autofill, sent } = setup({ isShown: () => shown });
    expect(autofill.attempt(detect())).toBe(false);
    shown = true;
    expect(autofill.attempt(detect())).toBe(true);
    expect(sent).toHaveLength(1);
  });

  test("a form without a password field is not a login form for this", () => {
    render(`<form><input id="u" type="text"></form>`);
    const filler = { request: vi.fn(() => true) };
    const autofill = createAutofill({
      filler,
      isTopFrame: () => true,
      protocol: () => "https:",
      isShown: () => true,
    });
    expect(autofill.attempt(detect())).toBe(false);
    expect(filler.request).not.toHaveBeenCalled();
  });
});
