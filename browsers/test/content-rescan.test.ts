// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";
import {
  affectsForms,
  createRescanScheduler,
  RESCAN_DEBOUNCE_MS,
  RESCAN_MAX_WAIT_MS,
} from "../src/content/rescan.ts";

describe("affectsForms", () => {
  let observer: MutationObserver;

  beforeEach(() => {
    document.body.innerHTML = `<main id="app"><div id="banner"></div><div id="wrap"><input id="u"></div></main>`;
    observer = new MutationObserver(() => undefined);
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["style", "class", "hidden", "disabled", "readonly", "type"],
    });
  });

  afterEach(() => {
    observer.disconnect();
  });

  const records = () => observer.takeRecords();

  it("counts a form rendered by a single-page app", () => {
    document
      .getElementById("app")!
      .insertAdjacentHTML("beforeend", `<form><input type="password"></form>`);
    expect(affectsForms(records())).toBe(true);
  });

  it("counts custom elements, whose fields live in a shadow root the observer cannot see", () => {
    document.getElementById("banner")!.innerHTML = `<section><x-login></x-login></section>`;
    expect(affectsForms(records())).toBe(true);
    const host = document.createElement("div");
    host.attachShadow({ mode: "open" }).innerHTML = `<input type="password">`;
    document.getElementById("banner")!.append(host);
    expect(affectsForms(records())).toBe(true);
  });

  it("counts removed fields and visibility changes on a field or its ancestors", () => {
    document.getElementById("u")!.remove();
    expect(affectsForms(records())).toBe(true);
    document.body.innerHTML = `<div id="wrap"><input id="u"></div>`;
    records();
    document.getElementById("wrap")!.setAttribute("style", "display: none");
    expect(affectsForms(records())).toBe(true);
    document.getElementById("u")!.setAttribute("hidden", "");
    expect(affectsForms(records())).toBe(true);
  });

  it("ignores animations, text and markup that cannot hold a field", () => {
    const banner = document.getElementById("banner")!;
    banner.setAttribute("style", "opacity: 0.5");
    banner.className = "pulse";
    banner.innerHTML = `<p>Sale <b>today</b></p>`;
    banner.append("tick");
    expect(affectsForms(records())).toBe(false);
  });
});

describe("rescan scheduler", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("flushes once a burst settles and says whether anything relevant happened", () => {
    const flush = vi.fn();
    const scheduler = createRescanScheduler(flush);
    scheduler.schedule(false);
    scheduler.schedule(true);
    scheduler.schedule(false);
    vi.advanceTimersByTime(RESCAN_DEBOUNCE_MS - 1);
    expect(flush).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(flush.mock.calls).toEqual([[true]]);
    scheduler.schedule(false);
    vi.advanceTimersByTime(RESCAN_DEBOUNCE_MS);
    expect(flush.mock.calls).toEqual([[true], [false]]);
  });

  it("still flushes while a page mutates faster than the debounce, at the max wait", () => {
    const flush = vi.fn();
    const scheduler = createRescanScheduler(flush);
    const step = RESCAN_DEBOUNCE_MS / 2;
    for (let t = 0; t < 3 * RESCAN_MAX_WAIT_MS; t += step) {
      scheduler.schedule(true);
      vi.advanceTimersByTime(step);
    }
    expect(flush).toHaveBeenCalledTimes(3);
  });

  it("cancel drops a pending flush", () => {
    const flush = vi.fn();
    const scheduler = createRescanScheduler(flush);
    scheduler.schedule(true);
    scheduler.cancel();
    vi.advanceTimersByTime(RESCAN_MAX_WAIT_MS);
    expect(flush).not.toHaveBeenCalled();
  });
});
