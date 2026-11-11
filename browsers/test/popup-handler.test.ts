import { describe, expect, it, vi } from "vite-plus/test";
import { createPopupHandler, type PopupDeps } from "../src/background/popup-handler.ts";
import type { BeginFillResult } from "../src/background/router.ts";
import type { PopupStatus } from "../src/shared/popup.ts";

const POPUP_URL = "chrome-extension://ext-id/popup.html";
const STATUS: PopupStatus = {
  phase: "ready",
  state: "unlocked",
  theme: "dark",
  fingerprint: "AAAA-BBBB-CCCC-DDDD",
  reason: null,
};

function setup(options: { tabId?: number | undefined; fill?: BeginFillResult } = {}) {
  const beginFill = vi.fn(
    async (_tabId: number, _choose: boolean) =>
      options.fill ?? ({ reached: true, found: true } as BeginFillResult),
  );
  const request = vi.fn(async () => ({}));
  const ensureReady = vi.fn(async () => undefined);
  const deps: PopupDeps = {
    runtimeId: "ext-id",
    popupUrl: POPUP_URL,
    activeTabId: async () => ("tabId" in options ? options.tabId : 7),
    beginFill,
    session: {
      status: STATUS,
      ensureReady,
      request: request as unknown as PopupDeps["session"]["request"],
    },
  };
  return { handle: createPopupHandler(deps), beginFill, request, ensureReady };
}

const FROM_POPUP = { id: "ext-id", url: POPUP_URL };

describe("popup handler", () => {
  it("replies ok/found on success", async () => {
    const { handle, beginFill } = setup();
    expect(await handle({ kind: "popup_fill", choose: true }, FROM_POPUP)).toEqual({
      ok: true,
      found: true,
    });
    expect(beginFill).toHaveBeenCalledWith(7, true);
  });

  it("replies found: false when the page has no login form", async () => {
    const { handle } = setup({ fill: { reached: true, found: false } });
    expect(await handle({ kind: "popup_fill", choose: false }, FROM_POPUP)).toEqual({
      ok: true,
      found: false,
    });
  });

  it("replies unreachable when the page cannot be reached", async () => {
    const { handle } = setup({ fill: { reached: false } });
    expect(await handle({ kind: "popup_fill", choose: false }, FROM_POPUP)).toEqual({
      ok: false,
      reason: "unreachable",
    });
  });

  it("replies unreachable when there is no active tab", async () => {
    const { handle, beginFill } = setup({ tabId: undefined });
    expect(await handle({ kind: "popup_fill", choose: false }, FROM_POPUP)).toEqual({
      ok: false,
      reason: "unreachable",
    });
    expect(beginFill).not.toHaveBeenCalled();
  });

  it("returns the status snapshot and kicks off the connection", async () => {
    const { handle, ensureReady } = setup();
    expect(await handle({ kind: "popup_status" }, FROM_POPUP)).toEqual({ status: STATUS });
    expect(ensureReady).toHaveBeenCalledOnce();
  });

  it("forwards unlock and open_app to the app", async () => {
    const { handle, request } = setup();
    expect(await handle({ kind: "popup_unlock" }, FROM_POPUP)).toEqual({ ok: true });
    expect(await handle({ kind: "popup_open_app", view: "settings" }, FROM_POPUP)).toEqual({
      ok: true,
    });
    expect(request).toHaveBeenNthCalledWith(1, "unlock", {});
    expect(request).toHaveBeenNthCalledWith(2, "open_app", { view: "settings" });
  });

  it("refuses senders that are not the popup page", async () => {
    const { handle, beginFill, request } = setup();
    const message = { kind: "popup_fill", choose: false } as const;
    for (const sender of [
      { id: "other", url: POPUP_URL },
      { id: "ext-id", url: "https://evil.example/" },
      { id: "ext-id", url: POPUP_URL, tab: { id: 1 } },
    ]) {
      expect(await handle(message, sender)).toEqual({ ok: false });
    }
    expect(beginFill).not.toHaveBeenCalled();
    expect(request).not.toHaveBeenCalled();
  });
});
