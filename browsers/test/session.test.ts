import { describe, expect, it } from "vite-plus/test";
import { NativeClient, type PortLike } from "../src/background/native.ts";
import {
  exportPublicKey,
  getOrCreateKeyPair,
  proofMessage,
  resetKeyPairCache,
  fromBase64,
  type KeyStore,
} from "../src/background/pairing.ts";
import { Session } from "../src/background/session.ts";
import type { PopupStatus } from "../src/shared/popup.ts";

function fakePort() {
  const listeners = {
    message: [] as ((m: unknown) => void)[],
    close: [] as ((p: PortLike) => void)[],
  };
  const sent: Record<string, unknown>[] = [];
  const port: PortLike & { sent: typeof sent; emit(m: unknown): void } = {
    sent,
    error: null,
    postMessage: (m) => void sent.push(m as Record<string, unknown>),
    disconnect: () => undefined,
    onMessage: { addListener: (fn) => void listeners.message.push(fn) },
    onDisconnect: { addListener: (fn) => void listeners.close.push(fn) },
    emit: (m) => listeners.message.forEach((fn) => fn(m)),
  };
  return port;
}

const store = (): KeyStore => {
  let pair: CryptoKeyPair | undefined;
  return { load: async () => pair, save: async (p) => void (pair = p) };
};

async function flush(): Promise<void> {
  for (let i = 0; i < 20; i++) {
    await new Promise((r) => setTimeout(r, 0));
  }
}

describe("Session handshake", () => {
  it("runs hello then prove with a verifiable signature and reports ready", async () => {
    resetKeyPairCache();
    const keys = store();
    const port = fakePort();
    const native = new NativeClient({ connectNative: () => port });
    const changes: PopupStatus[] = [];
    const caller = "chrome-extension://abc/";
    const session = new Session({
      native,
      keys: () => getOrCreateKeyPair(keys),
      caller,
      extensionVersion: "0.1.0",
      onChange: (s) => changes.push(s),
    });

    const ready = session.ensureReady();
    await flush();
    const hello = port.sent[0]!;
    expect(hello).toMatchObject({ id: 1, type: "hello", protocol: 1, extension_version: "0.1.0" });
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    port.emit({
      id: 1,
      ok: true,
      result: { challenge: btoa(String.fromCharCode(...challenge)), known: false },
    });
    await flush();
    expect(session.status.phase).toBe("pairing");
    expect(session.status.fingerprint).toMatch(/^[0-9A-F]{4}(-[0-9A-F]{4}){3}$/);

    const prove = port.sent[1]!;
    expect(prove).toMatchObject({ id: 2, type: "prove" });
    const pair = await getOrCreateKeyPair(keys);
    const publicKey = await crypto.subtle.importKey(
      "raw",
      (await exportPublicKey(pair)) as BufferSource,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      fromBase64(prove.signature as string) as BufferSource,
      proofMessage(challenge, caller) as BufferSource,
    );
    expect(ok).toBe(true);

    port.emit({ id: 2, ok: true, result: { state: "locked", theme: "dark", fingerprint: "x" } });
    await ready;
    expect(session.status).toMatchObject({ phase: "ready", state: "locked", theme: "dark" });
    expect(changes.at(-1)?.phase).toBe("ready");
  });

  it("marks the session denied when pairing is refused", async () => {
    resetKeyPairCache();
    const port = fakePort();
    const native = new NativeClient({ connectNative: () => port });
    const session = new Session({
      native,
      keys: () => getOrCreateKeyPair(store()),
      caller: "c",
      extensionVersion: "0.1.0",
      onChange: () => undefined,
    });
    const ready = session.ensureReady();
    const assertion = expect(ready).rejects.toMatchObject({ code: "denied" });
    await flush();
    port.emit({ id: 1, ok: true, result: { challenge: btoa("x".repeat(32)), known: true } });
    await flush();
    port.emit({ id: 2, ok: false, error: "denied" });
    await assertion;
    expect(session.status.phase).toBe("denied");
  });

  it("reports unavailable with the host's reason", async () => {
    resetKeyPairCache();
    const port = fakePort();
    const native = new NativeClient({ connectNative: () => port });
    const session = new Session({
      native,
      keys: () => getOrCreateKeyPair(store()),
      caller: "c",
      extensionVersion: "0.1.0",
      onChange: () => undefined,
    });
    const ready = session.ensureReady();
    const assertion = expect(ready).rejects.toMatchObject({ code: "unavailable" });
    await flush();
    port.emit({ event: "unavailable", reason: "not_running" });
    await flush();
    expect(session.status).toMatchObject({ phase: "unavailable", reason: "not_running" });
    native.disconnect(); // the host closes the port after announcing why
    await assertion;
  });
});
