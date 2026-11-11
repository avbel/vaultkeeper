// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, test } from "vite-plus/test";
import { createCapture, type Capture, type SaveCandidate } from "../src/content/capture.ts";
import { createFiller } from "../src/content/fill.ts";
import type { LoginForm } from "../src/content/detect.ts";
import {
  detect,
  input,
  keystroke,
  pressEnter,
  render,
  type as typeInto,
  visible,
} from "./content-dom.ts";

let capture: Capture | undefined;
let forms: LoginForm[] = [];
let emitted: SaveCandidate[] = [];
let clock = 0;

function start(html: string): void {
  render(html);
  emitted = [];
  clock = 0;
  forms = detect();
  capture = createCapture({
    forms: () => forms,
    rescan: () => (forms = detect()),
    emit: (c) => emitted.push(c),
    isTrusted: () => true,
    path: () => "/login",
    now: () => clock,
  });
}

const synthSubmit = (selector = "form") =>
  document
    .querySelector(selector)!
    .dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));

const submit = (selector = "form") => {
  pressEnter(document.querySelector(selector)!);
  synthSubmit(selector);
};

beforeEach(() => {
  document.body.innerHTML = "";
});
afterEach(() => {
  capture?.dispose();
});

const LOGIN = `<form id="f"><input id="u" type="email"><input id="p" type="password"><button type="submit">Go</button></form>`;

describe("capture", () => {
  test("submit emits one candidate", () => {
    start(LOGIN);
    typeInto(input("#u"), "alice@example.com");
    typeInto(input("#p"), "hunter2");
    submit();
    submit();
    expect(emitted).toEqual([
      { username: "alice@example.com", password: "hunter2", candidate: "login", path: "/login" },
    ]);
  });

  test("a trusted click on a submit control emits once, then the submit does not repeat it", () => {
    start(LOGIN);
    typeInto(input("#p"), "hunter2");
    document.querySelector("button")!.dispatchEvent(new Event("click", { bubbles: true }));
    submit();
    expect(emitted).toHaveLength(1);
  });

  test("a button whose text looks like sign in counts", () => {
    start(
      `<div><input id="u" type="text"><input id="p" type="password"><button type="button">Sign in</button><button type="button" id="x">Show</button></div>`,
    );
    typeInto(input("#p"), "pw");
    document.getElementById("x")!.dispatchEvent(new Event("click", { bubbles: true }));
    expect(emitted).toHaveLength(0);
    document.querySelector("button")!.dispatchEvent(new Event("click", { bubbles: true }));
    expect(emitted).toHaveLength(1);
  });

  test("Enter in the password field emits", () => {
    start(LOGIN);
    typeInto(input("#p"), "pw");
    input("#p").dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    expect(emitted).toHaveLength(1);
  });

  test("untrusted events do not count as typing", () => {
    start(LOGIN);
    capture!.dispose();
    capture = createCapture({
      forms: () => forms,
      rescan: () => forms,
      emit: (c) => emitted.push(c),
      path: () => "/login",
    });
    typeInto(input("#p"), "pw");
    submit();
    expect(emitted).toEqual([]);
  });

  test("values we filled ourselves emit nothing", () => {
    start(LOGIN);
    const filler = createFiller({
      send: (m) => {
        if (m.kind === "fill_request") {
          filler.applyResult({
            kind: "fill_result",
            nonce: m.nonce,
            username: "alice",
            password: "vaulted",
            theme: "system",
          });
        }
      },
      onFilled: (el) => capture!.markFilled(el),
      isVisible: visible,
    });
    typeInto(input("#p"), "typed-before");
    filler.request(forms[0]!, false);
    expect(input("#p").value).toBe("vaulted");
    submit();
    expect(emitted).toEqual([]);
  });

  test("clearing a filled value and typing counts as typed", () => {
    start(LOGIN);
    const filler = createFiller({
      send: (m) => {
        if (m.kind === "fill_request") {
          filler.applyResult({
            kind: "fill_result",
            nonce: m.nonce,
            username: "alice",
            password: "vaulted",
            theme: "system",
          });
        }
      },
      onFilled: (el) => capture!.markFilled(el),
      isVisible: visible,
    });
    filler.request(forms[0]!, false);
    typeInto(input("#p"), "vaulted!");
    submit();
    expect(emitted).toMatchObject([{ username: "alice", password: "vaulted!" }]);
  });

  test("equal new-password values emit kind change", () => {
    start(
      `<form><input id="u" type="text"><input id="a" type="password"><input id="b" type="password"></form>`,
    );
    typeInto(input("#a"), "n3w");
    typeInto(input("#b"), "n3w");
    submit();
    expect(emitted).toMatchObject([{ candidate: "change", password: "n3w" }]);
  });

  test("different new-password values emit nothing", () => {
    start(
      `<form><input type="text"><input id="a" type="password"><input id="b" type="password"></form>`,
    );
    typeInto(input("#a"), "one");
    typeInto(input("#b"), "two");
    submit();
    expect(emitted).toEqual([]);
  });

  test("no typed password emits nothing", () => {
    start(LOGIN);
    typeInto(input("#u"), "alice");
    submit();
    expect(emitted).toEqual([]);
  });

  test("retyping after an emission allows a new candidate", () => {
    start(LOGIN);
    typeInto(input("#p"), "wrong");
    submit();
    typeInto(input("#p"), "right");
    submit();
    expect(emitted.map((c) => c.password)).toEqual(["wrong", "right"]);
  });

  test("removing the typed password field emits via refresh", () => {
    start(LOGIN);
    typeInto(input("#u"), "alice");
    typeInto(input("#p"), "pw");
    document.getElementById("f")!.remove();
    capture!.refresh(detect());
    expect(emitted).toMatchObject([{ username: "alice", password: "pw" }]);
  });

  test("pagehide emits pending candidates", () => {
    start(LOGIN);
    typeInto(input("#p"), "pw");
    window.dispatchEvent(new Event("pagehide"));
    expect(emitted).toHaveLength(1);
  });

  test("multi-step login reuses the username typed on the earlier step", () => {
    start(
      `<form id="one"><input id="u" name="email" type="email" autocomplete="username"><button type="submit">Next</button></form>`,
    );
    typeInto(input("#u"), "alice@example.com");
    submit("#one");
    expect(emitted).toEqual([]);
    document.body.innerHTML = `<form id="two"><input id="p" type="password"><button type="submit">Log in</button></form>`;
    forms = detect();
    capture!.refresh(forms);
    typeInto(input("#p"), "pw");
    submit("#two");
    expect(emitted).toMatchObject([{ username: "alice@example.com", password: "pw" }]);
  });

  test("a value rewritten by a beforeinput handler emits nothing", () => {
    start(LOGIN);
    const rewrite = (event: Event) => {
      if (event.target === input("#p")) {
        input("#p").value = "guess";
      }
    };
    window.addEventListener("beforeinput", rewrite, true);
    keystroke(input("#p"), "x");
    window.removeEventListener("beforeinput", rewrite, true);
    expect(input("#p").value).toBe("guessx");
    submit();
    expect(emitted).toEqual([]);
  });

  test("backspace and paste keep the typed model in step with the value", () => {
    start(LOGIN);
    const el = input("#p");
    typeInto(el, "abc");
    el.value = "ab";
    el.dispatchEvent(
      new InputEvent("input", { bubbles: true, inputType: "deleteContentBackward" }),
    );
    el.value += "XY";
    el.dispatchEvent(
      new InputEvent("input", { bubbles: true, inputType: "insertFromPaste", data: "XY" }),
    );
    submit();
    expect(emitted).toMatchObject([{ password: "abXY" }]);
  });

  test("an edit that cannot be modelled emits nothing until the field is emptied", () => {
    start(LOGIN);
    const el = input("#p");
    typeInto(el, "abc");
    el.value = "aXc";
    el.dispatchEvent(
      new InputEvent("input", { bubbles: true, inputType: "insertReplacementText" }),
    );
    submit();
    expect(emitted).toEqual([]);
    typeInto(el, "fresh");
    submit();
    expect(emitted).toMatchObject([{ password: "fresh" }]);
  });

  test("a synthetic submit emits nothing", () => {
    start(LOGIN);
    typeInto(input("#p"), "pw");
    synthSubmit();
    expect(emitted).toEqual([]);
  });

  test("a submit long after the last trusted click or Enter emits nothing", () => {
    start(LOGIN);
    typeInto(input("#p"), "pw");
    pressEnter(document.getElementById("f")!);
    clock += 2_500;
    synthSubmit();
    expect(emitted).toEqual([]);
  });

  test("a detached field emits nothing without a recent trusted interaction", () => {
    start(LOGIN);
    typeInto(input("#p"), "pw");
    clock += 31_000;
    document.getElementById("f")!.remove();
    capture!.refresh(detect());
    expect(emitted).toEqual([]);
  });

  test("pagehide emits nothing without a recent trusted interaction", () => {
    start(LOGIN);
    typeInto(input("#p"), "pw");
    clock += 31_000;
    window.dispatchEvent(new Event("pagehide"));
    expect(emitted).toEqual([]);
  });

  test("multi-step login without a form: Next click remembers the username", () => {
    start(
      `<div id="one"><input id="u" type="email" autocomplete="username"><div role="button" id="next">Next</div></div>`,
    );
    typeInto(input("#u"), "alice@example.com");
    document.getElementById("next")!.dispatchEvent(new Event("click", { bubbles: true }));
    expect(emitted).toEqual([]);
    document.body.innerHTML = `<div id="two"><input id="p" type="password"><div role="button">Next</div></div>`;
    forms = detect();
    capture!.refresh(forms);
    typeInto(input("#p"), "pw");
    pressEnter(input("#p"));
    expect(emitted).toMatchObject([{ username: "alice@example.com", password: "pw" }]);
  });

  test("Enter in a username-only field is a safe trigger that emits nothing", () => {
    start(
      `<div><input id="u" type="email" autocomplete="username"><button type="button">Next</button></div>`,
    );
    typeInto(input("#u"), "alice");
    pressEnter(input("#u"));
    expect(emitted).toEqual([]);
  });
});
