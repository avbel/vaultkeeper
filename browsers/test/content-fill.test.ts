// @vitest-environment jsdom
import { beforeEach, describe, expect, test, vi } from "vite-plus/test";
import { createFiller, NONCE_TTL_MS } from "../src/content/fill.ts";
import type { ToBackground } from "../src/shared/messages.ts";
import { detect, input, render } from "./content-dom.ts";
import { visible } from "./content-dom.ts";

function setup(overrides: { origin?: () => string; now?: () => number } = {}) {
  render(`<form><input id="u" type="text"><input id="p" type="password"></form>`);
  const sent: ToBackground[] = [];
  const filled: HTMLInputElement[] = [];
  const filler = createFiller({
    send: (m) => sent.push(m),
    onFilled: (el) => filled.push(el),
    isVisible: visible,
    path: () => "/login",
    ...overrides,
  });
  const form = detect()[0]!;
  return { filler, form, sent, filled };
}

const result = (nonce: string, username: string | null, password: string | null) =>
  ({ kind: "fill_result", nonce, username, password, theme: "system" }) as const;

const nonceOf = (sent: ToBackground[]): string => {
  const first = sent[0];
  if (first?.kind !== "fill_request") {
    throw new Error("no request");
  }
  return first.nonce;
};

beforeEach(() => {
  document.body.innerHTML = "";
});

describe("fill", () => {
  test("sends a request without any origin and fills with events", () => {
    const { filler, form, sent, filled } = setup();
    expect(filler.request(form, true)).toBe(true);
    expect(sent[0]).toMatchObject({
      kind: "fill_request",
      choose: true,
      fields: { username: true, password: true },
      path: "/login",
    });
    expect(JSON.stringify(sent[0])).not.toContain("origin");
    const events: string[] = [];
    for (const type of ["input", "change"]) {
      input("#p").addEventListener(type, () => events.push(`${type}:${input("#p").value}`));
    }
    const outcome = filler.applyResult(result(nonceOf(sent), "alice", "s3cret"));
    expect(outcome).toEqual({ claimed: true, filled: 2 });
    expect(input("#u").value).toBe("alice");
    expect(input("#p").value).toBe("s3cret");
    expect(events).toEqual(["input:s3cret", "change:s3cret"]);
    expect(filled).toEqual([input("#u"), input("#p")]);
  });

  test("random 128-bit nonce", () => {
    const { filler, form, sent } = setup();
    filler.request(form, false);
    expect(nonceOf(sent)).toMatch(/^[0-9a-f]{32}$/);
  });

  test("wrong nonce is ignored and keeps the pending request", () => {
    const { filler, form, sent } = setup();
    filler.request(form, false);
    expect(filler.applyResult(result("0".repeat(32), "alice", "pw"))).toEqual({
      claimed: false,
      filled: 0,
    });
    expect(input("#u").value).toBe("");
    expect(filler.applyResult(result(nonceOf(sent), "alice", "pw")).claimed).toBe(true);
  });

  test("a nonce works once", () => {
    const { filler, form, sent } = setup();
    filler.request(form, false);
    const nonce = nonceOf(sent);
    filler.applyResult(result(nonce, "a", "b"));
    expect(filler.applyResult(result(nonce, "x", "y")).claimed).toBe(false);
    expect(input("#u").value).toBe("a");
  });

  test("changed origin is ignored", () => {
    let origin = "https://example.com";
    const { filler, form, sent } = setup({ origin: () => origin });
    filler.request(form, false);
    origin = "https://evil.example";
    expect(filler.applyResult(result(nonceOf(sent), "alice", "pw")).claimed).toBe(false);
    expect(input("#p").value).toBe("");
  });

  test("expired nonce is ignored", () => {
    let now = 1_000;
    const { filler, form, sent } = setup({ now: () => now });
    filler.request(form, false);
    now += NONCE_TTL_MS;
    expect(filler.applyResult(result(nonceOf(sent), "alice", "pw")).claimed).toBe(false);
  });

  test("a second request is blocked while one is pending", () => {
    const { filler, form, sent } = setup();
    expect(filler.request(form, false)).toBe(true);
    expect(filler.request(form, false)).toBe(false);
    expect(sent).toHaveLength(1);
  });

  test("fields removed or hidden after the request are not filled", () => {
    const { filler, form, sent } = setup();
    filler.request(form, false);
    input("#p").setAttribute("style", "display: none");
    input("#u").remove();
    expect(filler.applyResult(result(nonceOf(sent), "alice", "pw"))).toEqual({
      claimed: true,
      filled: 0,
    });
    expect(input("#p").value).toBe("");
  });

  test("password is never written to a text field", () => {
    const { filler, form, sent } = setup();
    filler.request(form, false);
    input("#p").type = "text";
    const outcome = filler.applyResult(result(nonceOf(sent), null, "s3cret"));
    expect(outcome.filled).toBe(0);
    expect(input("#p").value).toBe("");
    expect(input("#u").value).toBe("");
  });

  test("password is not written into a new-password field", () => {
    const { filler, form, sent } = setup();
    filler.request(form, false);
    input("#p").setAttribute("autocomplete", "new-password");
    expect(filler.applyResult(result(nonceOf(sent), null, "s3cret")).filled).toBe(0);
  });

  test("a sign-in field already marked new-password at request time is filled", () => {
    render(
      `<form id="signin-form"><input id="u" type="text"><input id="p" type="password" autocomplete="new-password"><button type="submit">Sign In</button></form>`,
    );
    const sent: ToBackground[] = [];
    const filler = createFiller({ send: (m) => sent.push(m), isVisible: visible });
    filler.request(detect()[0]!, false);
    expect(filler.applyResult(result(nonceOf(sent), "alice", "s3cret")).filled).toBe(2);
    expect(input("#u").value).toBe("alice");
    expect(input("#p").value).toBe("s3cret");
  });

  test("username is not written into a password field", () => {
    const { filler, form, sent } = setup();
    form.username!.type = "password";
    filler.request(form, false);
    expect(filler.applyResult(result(nonceOf(sent), "alice", null)).filled).toBe(0);
  });

  test("an error with the right nonce is claimed once", () => {
    const { filler, form, sent } = setup();
    filler.request(form, false);
    const nonce = nonceOf(sent);
    const error = { kind: "fill_error", nonce, code: "locked", theme: "system" } as const;
    expect(filler.applyError({ ...error, nonce: "bad" })).toBe(false);
    expect(filler.applyError(error)).toBe(true);
    expect(filler.applyError(error)).toBe(false);
  });

  test("a form with no fillable field sends nothing", () => {
    render(
      `<form><input type="password" autocomplete="new-password"><input type="password"></form>`,
    );
    const send = vi.fn();
    const filler = createFiller({ send, isVisible: visible });
    expect(filler.request(detect()[0]!, false)).toBe(false);
    expect(send).not.toHaveBeenCalled();
  });
});
