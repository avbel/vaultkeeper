// @vitest-environment jsdom
import { beforeEach, describe, expect, test, vi } from "vite-plus/test";
import { createGenerator, fieldLimits } from "../src/content/generate.ts";
import type { ToBackground } from "../src/shared/messages.ts";
import { NATIVE_REQUEST_TIMEOUT_MS } from "../src/shared/protocol.ts";
import { detect, input, render, visible } from "./content-dom.ts";

const SIGN_UP = `<form><input type="email"><input id="a" type="password" maxlength="20"><input id="b" type="password" minlength="10" maxlength="32"></form>`;

let sent: ToBackground[] = [];
let generated: { fields: HTMLInputElement[]; value: string }[] = [];
let clock = 0;

function generator() {
  return createGenerator({
    send: (message) => sent.push(message),
    onGenerated: (_form, fields, value) => generated.push({ fields, value }),
    isVisible: visible,
    now: () => clock,
    origin: () => "https://shop.example",
  });
}

function nonce(): string {
  const last = sent.at(-1);
  if (last?.kind !== "generate_request") {
    throw new Error("no generate request");
  }
  return last.nonce;
}

const result = (n: string, password = "Gen3rated!") =>
  ({ kind: "generate_result", nonce: n, password, saves: true, theme: "dark" }) as const;

beforeEach(() => {
  document.body.innerHTML = "";
  sent = [];
  generated = [];
  clock = 0;
});

describe("generator", () => {
  test("asks with the tightest limits of the password and its confirmation", () => {
    render(SIGN_UP);
    expect(generator().request(detect()[0]!, input("#a"))).toBe("sent");
    expect(sent).toMatchObject([
      { kind: "generate_request", limits: { min_length: 10, max_length: 20 } },
    ]);
    expect(fieldLimits([document.createElement("input")])).toEqual({
      min_length: null,
      max_length: null,
    });
  });

  test("fills the password and its confirmation with the same value", () => {
    render(SIGN_UP);
    const g = generator();
    g.request(detect()[0]!, input("#a"));
    const onInput = vi.fn();
    input("#b").addEventListener("input", onInput);
    expect(g.applyResult(result(nonce()))).toBe("filled");
    expect(input("#a").value).toBe("Gen3rated!");
    expect(input("#b").value).toBe("Gen3rated!");
    expect(onInput).toHaveBeenCalledOnce();
    expect(generated).toEqual([{ fields: [input("#a"), input("#b")], value: "Gen3rated!" }]);
  });

  test("a value the page rewrites is reported and not offered for saving", () => {
    render(SIGN_UP);
    const g = generator();
    g.request(detect()[0]!, input("#a"));
    input("#b").addEventListener("input", () => {
      input("#b").value = input("#b").value.slice(0, 5);
    });
    expect(g.applyResult(result(nonce()))).toBe("changed");
    expect(generated).toEqual([]);
  });

  test("answers that are stale, foreign or late fill nothing", () => {
    render(SIGN_UP);
    const g = generator();
    g.request(detect()[0]!, input("#a"));
    expect(g.applyResult(result("other"))).toBe("ignored");
    clock = 200_000;
    g.request(detect()[0]!, input("#a"));
    clock = 400_000;
    expect(g.applyResult(result(nonce()))).toBe("ignored");
    expect(input("#a").value).toBe("");
    g.request(detect()[0]!, input("#a"));
    const n = nonce();
    expect(g.applyError({ kind: "generate_error", nonce: n, code: "locked", theme: "dark" })).toBe(
      true,
    );
    expect(g.applyResult(result(n))).toBe("ignored");
  });

  test("the app's timeout error, which arrives after the native timeout, is still claimed", () => {
    render(SIGN_UP);
    const g = generator();
    g.request(detect()[0]!, input("#a"));
    clock += NATIVE_REQUEST_TIMEOUT_MS + 1_000;
    expect(
      g.applyError({ kind: "generate_error", nonce: nonce(), code: "timeout", theme: "dark" }),
    ).toBe(true);
  });

  test("a cancelled request lets the next click ask again; another nonce cancels nothing", () => {
    render(SIGN_UP);
    const g = generator();
    g.request(detect()[0]!, input("#a"));
    expect(g.cancel("other")).toBe(false);
    expect(g.request(detect()[0]!, input("#a"))).toBe("pending");
    expect(g.cancel(nonce())).toBe(true);
    expect(g.request(detect()[0]!, input("#a"))).toBe("sent");
  });

  test("a field too short for a strong password is not asked for", () => {
    render(`<form><input type="password" id="a" autocomplete="new-password" maxlength="4"></form>`);
    expect(generator().request(detect()[0]!, input("#a"))).toBe("too_short");
    expect(sent).toEqual([]);
  });

  test("a second click while the first waits for an unlock keeps the first answer", () => {
    render(SIGN_UP);
    const g = generator();
    expect(g.request(detect()[0]!, input("#a"))).toBe("sent");
    const first = nonce();
    expect(g.request(detect()[0]!, input("#a"))).toBe("pending");
    expect(sent).toHaveLength(1);
    expect(g.applyResult(result(first))).toBe("filled");
  });

  test("a field holding text is left alone unless the menu was opened on it", () => {
    render(
      `<form><input id="a" type="password"><input id="b" type="password"><button>Change</button></form>`,
    );
    input("#a").value = "current-secret";
    const g = generator();
    g.request(detect()[0]!, input("#b"));
    expect(g.applyResult(result(nonce()))).toBe("filled");
    expect(input("#a").value).toBe("current-secret");
    expect(input("#b").value).toBe("Gen3rated!");
    expect(generated).toEqual([{ fields: [input("#b")], value: "Gen3rated!" }]);
  });
});
