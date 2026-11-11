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
      status: { phase: options.phase ?? "ready" },
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
