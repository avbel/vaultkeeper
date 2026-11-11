import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";
import { NativeClient, NativeError, type PortLike } from "../src/background/native.ts";
import type { NativeEvent } from "../src/shared/protocol.ts";

class FakePort implements PortLike {
  sent: Record<string, unknown>[] = [];
  error: { message?: string } | null = null;
  #messageListeners: ((m: unknown) => void)[] = [];
  #disconnectListeners: ((p: PortLike) => void)[] = [];
  disconnected = false;
  onMessage = { addListener: (fn: (m: unknown) => void) => void this.#messageListeners.push(fn) };
  onDisconnect = {
    addListener: (fn: (p: PortLike) => void) => void this.#disconnectListeners.push(fn),
  };

  postMessage(message: unknown): void {
    this.sent.push(message as Record<string, unknown>);
  }
  disconnect(): void {
    this.disconnected = true;
  }
  emit(message: unknown): void {
    this.#messageListeners.forEach((fn) => fn(message));
  }
  close(error?: string): void {
    this.error = error ? { message: error } : null;
    this.#disconnectListeners.forEach((fn) => fn(this));
  }
}

function setup(timeoutMs?: number) {
  const ports: FakePort[] = [];
  const names: string[] = [];
  const native = new NativeClient({
    connectNative(name) {
      names.push(name);
      const port = new FakePort();
      ports.push(port);
      return port;
    },
    ...(timeoutMs === undefined ? {} : { timeoutMs }),
  });
  return { native, ports, names };
}

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

describe("NativeClient", () => {
  it("connects lazily to the host name and numbers requests", async () => {
    const { native, ports, names } = setup();
    expect(ports).toHaveLength(0);
    const first = native.request("status", {});
    const second = native.request("status", {});
    expect(names).toEqual(["org.vaultkeeper.browser"]);
    const port = ports[0]!;
    expect(port.sent.map((m) => m.id)).toEqual([1, 2]);
    expect(port.sent[0]).toEqual({ id: 1, type: "status" });

    port.emit({ id: 2, ok: true, result: { state: "locked", theme: "dark" } });
    port.emit({ id: 1, ok: true, result: { state: "unlocked", theme: "light" } });
    await expect(first).resolves.toEqual({ state: "unlocked", theme: "light" });
    await expect(second).resolves.toEqual({ state: "locked", theme: "dark" });
  });

  it("rejects with the error code of a failure response", async () => {
    const { native, ports } = setup();
    const pending = native.request("unlock", {});
    ports[0]!.emit({ id: 1, ok: false, error: "locked" });
    await expect(pending).rejects.toMatchObject({ code: "locked" });
  });

  it("ignores responses with unknown ids and malformed messages", async () => {
    const { native, ports } = setup();
    const pending = native.request("status", {});
    ports[0]!.emit({ id: 99, ok: true, result: {} });
    ports[0]!.emit("junk");
    ports[0]!.emit(null);
    ports[0]!.emit({ id: 1, ok: true, result: { state: "locked", theme: "system" } });
    await expect(pending).resolves.toMatchObject({ state: "locked" });
  });

  it("times out after 130 seconds by default", async () => {
    const { native } = setup();
    const pending = native.request("fill", {
      origin: "https://a.example",
      path: "/",
      choose: false,
      fields: { username: true, password: true },
    });
    const assertion = expect(pending).rejects.toMatchObject({ code: "timeout" });
    await vi.advanceTimersByTimeAsync(129_999);
    await vi.advanceTimersByTimeAsync(1);
    await assertion;
  });

  it("a response after the timeout is dropped without error", async () => {
    const { native, ports } = setup(1000);
    const pending = native.request("status", {});
    const assertion = expect(pending).rejects.toMatchObject({ code: "timeout" });
    await vi.advanceTimersByTimeAsync(1000);
    await assertion;
    expect(() => ports[0]!.emit({ id: 1, ok: true, result: {} })).not.toThrow();
  });

  it("rejects every pending request on disconnect and reconnects on the next request", async () => {
    const { native, ports } = setup();
    const a = native.request("status", {});
    const b = native.request("status", {});
    const settled = Promise.allSettled([a, b]);
    ports[0]!.close("Native host has exited.");
    const results = await settled;
    for (const result of results) {
      expect(result.status).toBe("rejected");
      expect((result as PromiseRejectedResult).reason).toMatchObject({
        code: "unavailable",
        reason: "Native host has exited.",
      });
    }
    expect(native.connected).toBe(false);

    const again = native.request("status", {});
    expect(ports).toHaveLength(2);
    expect(ports[1]!.sent[0]).toMatchObject({ id: 3 });
    ports[1]!.emit({ id: 3, ok: true, result: { state: "locked", theme: "system" } });
    await expect(again).resolves.toMatchObject({ state: "locked" });
  });

  it("clears timers of requests rejected by a disconnect", async () => {
    const { native, ports } = setup();
    const pending = native.request("status", {}).catch(() => undefined);
    ports[0]!.close();
    await pending;
    expect(vi.getTimerCount()).toBe(0);
  });

  it("uses the unavailable event reason when the host then closes", async () => {
    const { native, ports } = setup();
    const events: NativeEvent[] = [];
    native.onEvent((e) => events.push(e));
    const pending = native.request("hello", {
      protocol: 1,
      extension_version: "0.1.0",
      public_key: "x",
    });
    ports[0]!.emit({ event: "unavailable", reason: "unverified_parent" });
    ports[0]!.close();
    await expect(pending).rejects.toMatchObject({
      code: "unavailable",
      reason: "unverified_parent",
    });
    expect(events[0]).toEqual({ event: "unavailable", reason: "unverified_parent" });
  });

  it("ignores ping events and forwards state events", () => {
    const { native, ports } = setup();
    const events: NativeEvent[] = [];
    native.onEvent((e) => events.push(e));
    native.connect();
    ports[0]!.emit({ event: "ping" });
    ports[0]!.emit({ event: "state", state: "locked", theme: "dark" });
    expect(events).toEqual([{ event: "state", state: "locked", theme: "dark" }]);
  });

  it("explicit disconnect rejects pending requests and closes the port", async () => {
    const { native, ports } = setup();
    const pending = native.request("status", {});
    const assertion = expect(pending).rejects.toBeInstanceOf(NativeError);
    native.disconnect();
    await assertion;
    expect(ports[0]!.disconnected).toBe(true);
  });

  it("a late disconnect of an old port does not drop the new connection", () => {
    const { native, ports } = setup();
    native.connect();
    ports[0]!.close();
    native.connect();
    ports[0]!.close();
    expect(native.connected).toBe(true);
  });
});
