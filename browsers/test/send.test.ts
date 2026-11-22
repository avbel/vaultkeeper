import { describe, expect, it, vi } from "vite-plus/test";
import { createSend, handleRefusal } from "../src/content/outbox.ts";
import { TOAST } from "../src/content/toast-text.ts";
import type { ToBackground } from "../src/shared/messages.ts";
import { forwardToBackground } from "../src/shared/send.ts";

const FILL: ToBackground = {
  kind: "fill_request",
  nonce: "n1",
  choose: false,
  auto: false,
  fields: { username: true, password: true },
  path: "/",
};
const GENERATE: ToBackground = {
  kind: "generate_request",
  nonce: "g1",
  limits: { min_length: null, max_length: null },
};
const SAVE: ToBackground = {
  kind: "save_candidate",
  username: "a",
  password: "p",
  candidate: "login",
  has_current: true,
  path: "/",
};

describe("forwardToBackground", () => {
  it("resolves false when sendMessage throws synchronously (invalidated context)", async () => {
    const send = () => {
      throw new Error("Extension context invalidated.");
    };
    await expect(forwardToBackground(send, FILL)).resolves.toBe(false);
  });

  it("resolves whether the background accepted the message", async () => {
    await expect(forwardToBackground(async () => ({ accepted: true }), FILL)).resolves.toBe(true);
    await expect(forwardToBackground(async () => ({ accepted: false }), FILL)).resolves.toBe(false);
    await expect(forwardToBackground(async () => undefined, FILL)).resolves.toBe(false);
    await expect(
      forwardToBackground(() => Promise.reject(new Error("no receiver")), FILL),
    ).resolves.toBe(false);
  });
});

function deps() {
  return {
    filler: { cancel: vi.fn((_nonce?: string) => true) },
    generator: { cancel: vi.fn((_nonce: string) => true) },
    toast: vi.fn(),
  };
}

describe("handleRefusal", () => {
  it("cancels the refused fill by its nonce and says so", () => {
    const d = deps();
    handleRefusal(FILL, d);
    expect(d.filler.cancel).toHaveBeenCalledWith("n1");
    expect(d.generator.cancel).not.toHaveBeenCalled();
    expect(d.toast).toHaveBeenCalledWith(TOAST.generic);
  });

  it("stays quiet for an automatic fill and for one no longer pending", () => {
    const auto = deps();
    handleRefusal({ ...FILL, auto: true } as ToBackground, auto);
    expect(auto.filler.cancel).toHaveBeenCalledWith("n1");
    expect(auto.toast).not.toHaveBeenCalled();
    const gone = deps();
    gone.filler.cancel.mockReturnValue(false);
    handleRefusal(FILL, gone);
    expect(gone.toast).not.toHaveBeenCalled();
  });

  it("cancels the generator, not the filler, for a refused generate request", () => {
    const d = deps();
    handleRefusal(GENERATE, d);
    expect(d.generator.cancel).toHaveBeenCalledWith("g1");
    expect(d.filler.cancel).not.toHaveBeenCalled();
    expect(d.toast).toHaveBeenCalledWith(TOAST.generateFailed);
  });

  it("leaves pending requests alone and says nothing for a save candidate", () => {
    const d = deps();
    handleRefusal(SAVE, d);
    expect(d.filler.cancel).not.toHaveBeenCalled();
    expect(d.generator.cancel).not.toHaveBeenCalled();
    expect(d.toast).not.toHaveBeenCalled();
  });
});

describe("createSend", () => {
  const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

  it("reports a message the background did not accept", async () => {
    const refused = vi.fn();
    const send = createSend({ forward: async () => false, refused, orphaned: () => false });
    send(FILL);
    await flush();
    expect(refused).toHaveBeenCalledWith(FILL);
  });

  it("does nothing more for an accepted message", async () => {
    const refused = vi.fn();
    const orphaned = vi.fn(() => false);
    const send = createSend({ forward: async () => true, refused, orphaned });
    send(FILL);
    await flush();
    expect(refused).not.toHaveBeenCalled();
    expect(orphaned).not.toHaveBeenCalled();
  });

  it("shuts down instead of reporting once the extension is gone", async () => {
    const refused = vi.fn();
    const send = createSend({ forward: async () => false, refused, orphaned: () => true });
    send(FILL);
    await flush();
    expect(refused).not.toHaveBeenCalled();
  });
});
