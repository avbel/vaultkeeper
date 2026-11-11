// @vitest-environment jsdom
import { beforeEach, expect, test, vi } from "vite-plus/test";
import { createIcon } from "../src/content/icon.ts";
import { readFileSync } from "node:fs";
import { toShadowTokens } from "../src/content/shadow-tokens.ts";
import { TOAST, toastForError } from "../src/content/toast-text.ts";

beforeEach(() => {
  document.body.innerHTML = "";
});

function parts(icon: ReturnType<typeof createIcon>) {
  const root = icon.host.shadowRoot!;
  return {
    button: root.querySelector("button")!,
    toast: root.querySelector<HTMLElement>(".toast")!,
  };
}

test("shadow root is closed by default", () => {
  expect(createIcon().host.shadowRoot).toBeNull();
});

test("only trusted clicks start a fill", () => {
  let trusted = false;
  const icon = createIcon({ shadowMode: "open", isTrusted: () => trusted });
  document.body.append(icon.host);
  const field = document.createElement("input");
  document.body.append(field);
  field.getClientRects = () => [{}] as unknown as DOMRectList;
  field.getBoundingClientRect = () => ({ right: 300, top: 100, height: 30 }) as DOMRect;
  const onClick = vi.fn();
  icon.show(field, onClick);
  const { button } = parts(icon);
  expect(button.hasAttribute("data-shown")).toBe(true);
  expect(button.style.left).toBe("276px");
  expect(button.style.top).toBe("105px");
  button.click();
  expect(onClick).not.toHaveBeenCalled();
  trusted = true;
  button.click();
  expect(onClick).toHaveBeenCalledOnce();
});

test("icon hides when its field disappears", () => {
  const icon = createIcon({ shadowMode: "open" });
  const field = document.createElement("input");
  document.body.append(field);
  field.getClientRects = () => [{}] as unknown as DOMRectList;
  field.getBoundingClientRect = () => ({ right: 300, top: 0, height: 20 }) as DOMRect;
  icon.show(field, () => {});
  field.getClientRects = () => [] as unknown as DOMRectList;
  icon.reposition();
  expect(parts(icon).button.hasAttribute("data-shown")).toBe(false);
});

test("theme is a data attribute on the host and absent for system", () => {
  const icon = createIcon();
  icon.setTheme("dark");
  expect(icon.host.getAttribute("data-theme")).toBe("dark");
  icon.setTheme("system");
  expect(icon.host.hasAttribute("data-theme")).toBe(false);
});

test("toast shows text then hides", () => {
  vi.useFakeTimers();
  const icon = createIcon({ shadowMode: "open" });
  icon.toast(TOAST.locked);
  const { toast } = parts(icon);
  expect(toast.textContent).toBe("Vaultkeeper is locked");
  expect(toast.hidden).toBe(false);
  vi.advanceTimersByTime(4000);
  expect(toast.hidden).toBe(true);
  vi.useRealTimers();
});

test("error codes map to toast text", () => {
  expect(toastForError("locked")).toBe("Vaultkeeper is locked");
  expect(toastForError("logged_out")).toBe("Vaultkeeper is locked");
  for (const code of ["cancelled", "denied", "no_login"] as const) {
    expect(toastForError(code)).toBe("No login chosen");
  }
  expect(toastForError("unavailable")).toBe("Vaultkeeper is not running");
  expect(toastForError("offline")).toBe("Vaultkeeper is not running");
  expect(toastForError("internal")).toBe("Vaultkeeper could not fill this page");
});

test("shadow tokens are the theme.css variables hung on :host", () => {
  const SHADOW_TOKENS = toShadowTokens(readFileSync("src/ui/theme.css", "utf8"));
  expect(SHADOW_TOKENS).not.toContain(":root");
  expect(SHADOW_TOKENS).toContain(':host([data-theme="dark"])');
  expect(SHADOW_TOKENS).toContain(':host(:not([data-theme="light"]))');
  expect(SHADOW_TOKENS).toContain("--accent:");
});
