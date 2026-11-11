// @vitest-environment jsdom
import { beforeEach, describe, expect, test } from "vite-plus/test";
import { findLoginForms, isVisible } from "../src/content/detect.ts";
import { detect, input, render } from "./content-dom.ts";

beforeEach(() => {
  document.body.innerHTML = "";
});

describe("findLoginForms", () => {
  test("simple form", () => {
    render(
      `<form id="f"><input name="email" type="email"><input type="password"><button>Log in</button></form>`,
    );
    const [form, ...rest] = detect();
    expect(rest).toHaveLength(0);
    expect(form?.username).toBe(input("[name=email]"));
    expect(form?.password).toBe(input("[type=password]"));
    expect(form?.newPasswords).toEqual([]);
    expect(form?.container).toBe(document.getElementById("f"));
  });

  test("no form element", () => {
    render(
      `<div id="box"><div><input type="text" id="u"></div><input type="password" id="p"></div><input type="text" id="search">`,
    );
    const [form] = detect();
    expect(form?.username).toBe(input("#u"));
    expect(form?.password).toBe(input("#p"));
    expect(form?.container).toBe(document.getElementById("box"));
  });

  test("username-only step", () => {
    render(`<form><input name="identifier"><button type="submit">Next</button></form>`);
    const [form, ...rest] = detect();
    expect(rest).toHaveLength(0);
    expect(form?.username).toBe(input("[name=identifier]"));
    expect(form?.password).toBeUndefined();
  });

  test("username-only step needs a submit control", () => {
    render(`<form><input name="identifier"></form>`);
    expect(detect()).toEqual([]);
  });

  test("signup with two password fields has only new passwords", () => {
    render(
      `<form><input type="email"><input type="password" id="a"><input type="password" id="b"></form>`,
    );
    const [form] = detect();
    expect(form?.password).toBeUndefined();
    expect(form?.newPasswords).toEqual([input("#a"), input("#b")]);
    expect(form?.username).toBe(input("[type=email]"));
  });

  test("current password stays current in a three-field change form", () => {
    render(
      `<form><input type="password" id="old"><input type="password" id="a"><input type="password" id="b"></form>`,
    );
    const [form] = detect();
    expect(form?.password).toBe(input("#old"));
    expect(form?.newPasswords).toEqual([input("#a"), input("#b")]);
  });

  test("autocomplete new-password marks a lone field as new", () => {
    render(`<form><input type="text"><input type="password" autocomplete="new-password"></form>`);
    const [form] = detect();
    expect(form?.password).toBeUndefined();
    expect(form?.newPasswords).toHaveLength(1);
  });

  test("hidden password field is ignored", () => {
    render(`<form><input type="text"><input type="password" style="display: none"></form>`);
    expect(detect()).toEqual([]);
  });

  test("field in an open shadow root", () => {
    render(`<div id="host"></div>`);
    const shadow = document.getElementById("host")!.attachShadow({ mode: "open" });
    shadow.innerHTML = `<form><input type="text" id="u"><input type="password" id="p"></form>`;
    const [form] = detect();
    expect(form?.username).toBe(input("#u", shadow));
    expect(form?.password).toBe(input("#p", shadow));
  });
});

describe("isVisible", () => {
  const stub = (el: HTMLInputElement, width: number, height: number, shown = true) => {
    el.getClientRects = () => (shown ? [{}] : []) as unknown as DOMRectList;
    el.getBoundingClientRect = () => ({ width, height }) as DOMRect;
  };

  test("requires layout, size, visibility and opacity", () => {
    render(
      `<input id="a"><input id="b" style="visibility: hidden"><input id="c" style="opacity: 0.05"><input id="d" disabled>`,
    );
    const [a, b, c, d] = ["a", "b", "c", "d"].map((id) => input(`#${id}`));
    for (const el of [a!, b!, c!, d!]) {
      stub(el, 100, 20);
    }
    expect(isVisible(a!)).toBe(true);
    expect(isVisible(b!)).toBe(false);
    expect(isVisible(c!)).toBe(false);
    expect(isVisible(d!)).toBe(false);
    stub(a!, 4, 20);
    expect(isVisible(a!)).toBe(false);
    stub(a!, 100, 20, false);
    expect(isVisible(a!)).toBe(false);
  });
});

test("findLoginForms with the default visibility check sees nothing without layout", () => {
  render(`<form><input type="text"><input type="password"></form>`);
  expect(findLoginForms(document)).toEqual([]);
});
