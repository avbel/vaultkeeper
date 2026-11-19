import { describe, expect, it, vi } from "vite-plus/test";
import { NativeError } from "../src/background/native.ts";
import { createRouter, type RouterDeps, type SenderLike } from "../src/background/router.ts";
import type { ToContent } from "../src/shared/messages.ts";

const RUNTIME_ID = "ext-id";
const PAGE = "https://shop.example/login?next=/a#frag";

function sender(overrides: Partial<SenderLike> = {}): SenderLike {
  return {
    id: RUNTIME_ID,
    url: PAGE,
    frameId: 0,
    tab: { id: 5, url: PAGE, incognito: false },
    ...overrides,
  };
}

function setup(
  options: {
    request?: RouterDeps["session"]["request"];
    tabUrl?: string;
    phase?: string;
    state?: string | null;
    sendToTab?: RouterDeps["sendToTab"];
  } = {},
) {
  const request = vi.fn(
    options.request ??
      (async (type: string) => (type === "fill" ? { username: "alice", password: "s3cret" } : {})),
  );
  const sent: { tabId: number; message: ToContent; frameId: number }[] = [];
  const injectContent = vi.fn(async (_tabId: number) => undefined);
  const deps: RouterDeps = {
    runtimeId: RUNTIME_ID,
    getTab: async () => ({ url: options.tabUrl ?? PAGE }),
    injectContent,
    sendToTab:
      options.sendToTab ??
      (async (tabId, message, frameId) => {
        sent.push({ tabId, message, frameId });
      }),
    session: {
      request: request as unknown as RouterDeps["session"]["request"],
      theme: "dark",
      status: {
        phase: options.phase ?? "ready",
        state: options.state === undefined ? "unlocked" : options.state,
      },
    },
  };
  return { router: createRouter(deps), request, sent, injectContent };
}

const FILL = {
  kind: "fill_request",
  nonce: "n1",
  choose: false,
  fields: { username: true, password: true },
  path: "/ignored",
};
const AUTO = { ...FILL, auto: true };

describe("router sender checks", () => {
  it("computes origin and path from the sender, ignoring body fields", async () => {
    const { router, request } = setup();
    const forged = { ...FILL, origin: "https://evil.example", path: "/evil" };
    expect(await router.handleContentMessage(forged, sender())).toEqual({ accepted: true });
    await router.idle();
    expect(request).toHaveBeenCalledWith("fill", {
      origin: "https://shop.example",
      path: "/login",
      choose: false,
      auto: false,
      fields: { username: true, password: true },
    });
  });

  it("refuses a frame whose origin differs from the tab origin", async () => {
    const { router, request } = setup();
    const result = await router.handleContentMessage(
      FILL,
      sender({ url: "https://ads.example/frame" }),
    );
    expect(result).toEqual({ accepted: false });
    await router.idle();
    expect(request).not.toHaveBeenCalled();
  });

  it("refuses a foreign sender id", async () => {
    const { router, request } = setup();
    expect(await router.handleContentMessage(FILL, sender({ id: "other-ext" }))).toEqual({
      accepted: false,
    });
    expect(await router.handleContentMessage(FILL, sender({ id: undefined }))).toEqual({
      accepted: false,
    });
    expect(request).not.toHaveBeenCalled();
  });

  it("refuses senders without a tab and non-web schemes", async () => {
    const { router, request } = setup();
    expect(await router.handleContentMessage(FILL, sender({ tab: undefined }))).toEqual({
      accepted: false,
    });
    const file = "file:///etc/hosts";
    expect(
      await router.handleContentMessage(FILL, sender({ url: file, tab: { id: 1, url: file } })),
    ).toEqual({ accepted: false });
    expect(request).not.toHaveBeenCalled();
  });

  it("refuses malformed messages", async () => {
    const { router, request } = setup();
    for (const bad of [
      null,
      "x",
      { kind: "fill_request" },
      { ...FILL, choose: "yes" },
      { kind: "other" },
    ]) {
      expect(await router.handleContentMessage(bad, sender())).toEqual({ accepted: false });
    }
    expect(request).not.toHaveBeenCalled();
  });
});

describe("fill flow", () => {
  it("sends the result to the requesting frame with the theme", async () => {
    const { router, sent } = setup();
    await router.handleContentMessage(FILL, sender({ frameId: 0 }));
    await router.idle();
    expect(sent).toEqual([
      {
        tabId: 5,
        frameId: 0,
        message: {
          kind: "fill_result",
          nonce: "n1",
          username: "alice",
          password: "s3cret",
          theme: "dark",
        },
      },
    ]);
  });

  it("drops the credential when the tab navigated to another origin", async () => {
    const { router, sent } = setup({ tabUrl: "https://phish.example/" });
    await router.handleContentMessage(FILL, sender());
    await router.idle();
    expect(sent).toEqual([]);
  });

  it("maps native errors to fill_error with the nonce", async () => {
    const { router, sent } = setup({
      request: async () => {
        throw new NativeError("locked");
      },
    });
    await router.handleContentMessage(FILL, sender());
    await router.idle();
    expect(sent[0]?.message).toEqual({
      kind: "fill_error",
      nonce: "n1",
      code: "locked",
      theme: "dark",
    });
  });

  it("reports unavailable when the host cannot be reached", async () => {
    const { router, sent } = setup({
      request: async () => {
        throw new NativeError("unavailable", "not_running");
      },
    });
    await router.handleContentMessage(FILL, sender());
    await router.idle();
    expect(sent[0]?.message).toMatchObject({ kind: "fill_error", code: "unavailable" });
  });
});

describe("automatic fill", () => {
  const QUIET = { kind: "fill_error", nonce: "n1", code: "no_auto", theme: "dark" };

  it("asks the app with auto set and delivers the result like a normal fill", async () => {
    const { router, request, sent } = setup();
    await router.handleContentMessage(AUTO, sender());
    await router.idle();
    expect(request).toHaveBeenCalledWith("fill", {
      origin: "https://shop.example",
      path: "/login",
      choose: false,
      auto: true,
      fields: { username: true, password: true },
    });
    expect(sent[0]?.message).toMatchObject({ kind: "fill_result", username: "alice" });
  });

  it("maps every failure, including no_auto, to a silent drop of the pending request", async () => {
    for (const code of ["no_auto", "locked", "rate_limited", "unavailable"] as const) {
      const { router, sent } = setup({
        request: async () => {
          throw new NativeError(code);
        },
      });
      await router.handleContentMessage(AUTO, sender());
      await router.idle();
      expect(sent.map((s) => s.message)).toEqual([QUIET]);
    }
  });

  it("does not touch the connection unless it is ready and unlocked", async () => {
    for (const options of [
      { phase: "idle" },
      { phase: "unavailable" },
      { phase: "denied" },
      { state: "locked" },
      { state: "logged_out" },
      { state: null },
    ]) {
      const { router, request, sent } = setup(options);
      await router.handleContentMessage(AUTO, sender());
      await router.idle();
      expect(request).not.toHaveBeenCalled();
      expect(sent.map((s) => s.message)).toEqual([QUIET]);
    }
  });

  it("refuses frames, http pages and a request that also asks for the picker", async () => {
    const http = "http://localhost:3000/login";
    const cases = [
      { message: AUTO, from: sender({ frameId: 3 }) },
      { message: AUTO, from: sender({ url: http, tab: { id: 5, url: http } }) },
      { message: { ...AUTO, choose: true }, from: sender() },
    ];
    for (const { message, from } of cases) {
      const { router, request, sent } = setup();
      await router.handleContentMessage(message, from);
      await router.idle();
      expect(request).not.toHaveBeenCalled();
      expect(sent.map((s) => s.message)).toEqual([QUIET]);
    }
  });

  it("a normal fill never carries auto, whatever the page claims", async () => {
    const { router, request } = setup();
    await router.handleContentMessage({ ...FILL, auto: "yes" }, sender());
    await router.handleContentMessage(FILL, sender());
    await router.idle();
    expect(request).toHaveBeenCalledTimes(1);
    expect(request).toHaveBeenCalledWith("fill", expect.objectContaining({ auto: false }));
  });
});

describe("save flow", () => {
  const SAVE = { kind: "save_candidate", username: "bob", password: "pw", candidate: "change" };

  it("forwards the candidate with the computed origin", async () => {
    const { router, request, sent } = setup();
    await router.handleContentMessage(SAVE, sender());
    await router.idle();
    expect(request).toHaveBeenCalledWith("save_candidate", {
      origin: "https://shop.example",
      path: "/login",
      username: "bob",
      password: "pw",
      kind: "change",
    });
    expect(sent).toEqual([]);
  });

  it("skips incognito tabs", async () => {
    const { router, request } = setup();
    await router.handleContentMessage(SAVE, sender({ tab: { id: 5, url: PAGE, incognito: true } }));
    await router.idle();
    expect(request).not.toHaveBeenCalled();
  });

  it("does not retry pairing after a denial", async () => {
    const { router, request } = setup({ phase: "denied" });
    await router.handleContentMessage(SAVE, sender());
    await router.idle();
    expect(request).not.toHaveBeenCalled();
  });

  it("swallows failures", async () => {
    const { router } = setup({
      request: async () => {
        throw new NativeError("rate_limited");
      },
    });
    await router.handleContentMessage(SAVE, sender());
    await expect(router.idle()).resolves.toBeUndefined();
  });
});

describe("begin_fill", () => {
  const NO_RECEIVER = new Error("Could not establish connection. Receiving end does not exist.");

  it("targets frame 0 and treats a missing reply as found", async () => {
    const { router, sent, injectContent } = setup();
    expect(await router.beginFill(9, true)).toEqual({ reached: true, found: true });
    expect(sent).toEqual([{ tabId: 9, frameId: 0, message: { kind: "begin_fill", choose: true } }]);
    expect(injectContent).not.toHaveBeenCalled();
  });

  it("passes on found: false from the content script", async () => {
    const { router } = setup({ sendToTab: async () => ({ found: false }) });
    expect(await router.beginFill(9, false)).toEqual({ reached: true, found: false });
  });

  it("injects the content script and resends once when there is no receiver", async () => {
    let injected = false;
    const calls: number[] = [];
    const { router, injectContent } = setup({
      sendToTab: async (tabId) => {
        calls.push(tabId);
        if (!injected) {
          throw NO_RECEIVER;
        }
        return { found: true };
      },
    });
    injectContent.mockImplementation(async () => {
      injected = true;
    });
    expect(await router.beginFill(9, false)).toEqual({ reached: true, found: true });
    expect(injectContent).toHaveBeenCalledExactlyOnceWith(9);
    expect(calls).toEqual([9, 9]);
  });

  it("gives up when the resend still fails", async () => {
    const { router, injectContent } = setup({
      sendToTab: async () => {
        throw NO_RECEIVER;
      },
    });
    expect(await router.beginFill(9, false)).toEqual({ reached: false });
    expect(injectContent).toHaveBeenCalledOnce();
  });

  it("reports unreachable when injection is refused (chrome:// pages, the Web Store)", async () => {
    const { router, injectContent } = setup({
      sendToTab: async () => {
        throw NO_RECEIVER;
      },
    });
    injectContent.mockRejectedValue(new Error("Cannot access a chrome:// URL"));
    expect(await router.beginFill(9, false)).toEqual({ reached: false });
  });

  it("never injects into tabs that are not http(s)", async () => {
    for (const tabUrl of ["chrome://extensions/", "file:///a.html", "about:blank"]) {
      const { router, injectContent } = setup({
        tabUrl,
        sendToTab: async () => {
          throw NO_RECEIVER;
        },
      });
      expect(await router.beginFill(9, false)).toEqual({ reached: false });
      expect(injectContent).not.toHaveBeenCalled();
    }
  });

  it("does not inject on errors other than a missing receiver", async () => {
    const { router, injectContent } = setup({
      sendToTab: async () => {
        throw new Error("The message port closed before a response was received.");
      },
    });
    expect(await router.beginFill(9, false)).toEqual({ reached: false });
    expect(injectContent).not.toHaveBeenCalled();
  });
});

describe("router passkeys", () => {
  const GET = {
    kind: "passkey_request",
    nonce: "p1",
    ceremony: "get",
    options: { challenge: "AQ" },
  };

  it("sends the vault's credential to the requesting frame with the sender's origin", async () => {
    const { router, request, sent } = setup({
      request: async () => ({ credential: { id: "AQ" } }),
    });
    expect(await router.handleContentMessage(GET, sender({ frameId: 3 }))).toEqual({
      accepted: true,
    });
    await router.idle();
    expect(request).toHaveBeenCalledWith("passkey_get", {
      origin: "https://shop.example",
      options: { challenge: "AQ" },
    });
    expect(sent).toEqual([
      {
        tabId: 5,
        frameId: 3,
        message: {
          kind: "passkey_result",
          nonce: "p1",
          outcome: "credential",
          credential: { id: "AQ" },
        },
      },
    ]);
  });

  it("passes refusals on and hands everything else to the browser", async () => {
    for (const [code, outcome] of [
      ["not_allowed", { outcome: "error", error: "not_allowed" }],
      ["invalid_state", { outcome: "error", error: "invalid_state" }],
      ["fallback", { outcome: "fallback" }],
      ["locked", { outcome: "fallback" }],
      ["unpaired", { outcome: "fallback" }],
    ] as const) {
      const { router, sent } = setup({
        request: async () => {
          throw new NativeError(code);
        },
      });
      await router.handleContentMessage({ ...GET, ceremony: "create" }, sender());
      await router.idle();
      expect(sent[0]?.message).toEqual({ kind: "passkey_result", nonce: "p1", ...outcome });
    }
  });

  it("does not wake an app the user refused or that is not installed", async () => {
    for (const phase of ["denied", "unavailable"]) {
      const { router, request, sent } = setup({ phase });
      await router.handleContentMessage(GET, sender());
      await router.idle();
      expect(request).not.toHaveBeenCalled();
      expect(sent[0]?.message).toEqual({
        kind: "passkey_result",
        nonce: "p1",
        outcome: "fallback",
      });
    }
  });

  it("drops the answer when the tab moved to another site meanwhile", async () => {
    const { router, sent } = setup({
      tabUrl: "https://elsewhere.example/",
      request: async () => ({ credential: { id: "AQ" } }),
    });
    await router.handleContentMessage(GET, sender());
    await router.idle();
    expect(sent).toEqual([]);
  });

  it("forwards a cancel for the sender's origin", async () => {
    const { router, request } = setup();
    await router.handleContentMessage({ kind: "passkey_cancel", nonce: "p1" }, sender());
    await router.idle();
    expect(request).toHaveBeenCalledWith("passkey_cancel", { origin: "https://shop.example" });
  });
});
