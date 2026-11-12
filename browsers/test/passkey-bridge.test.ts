// The page script and the relay together, as they run in one frame: the page's
// navigator.credentials call reaches the background, and the background's answer reaches the page.
import { beforeAll, describe, expect, it, vi } from "vite-plus/test";

const ORIGIN = "https://accounts.example.com";
type Listener = (message: unknown, sender: { id: string }) => void;

const sent: Record<string, unknown>[] = [];
const listeners: Listener[] = [];
let accepted = true;
const nativeGet = vi.fn(async () => "native get");
const nativeCreate = vi.fn(async () => "native create");

class FakeCredential {}
class FakeAssertion {}
class FakeAttestation {}

function installFakes(): void {
  const target = new EventTarget();
  const fakeWindow = {
    location: { origin: ORIGIN },
    addEventListener: target.addEventListener.bind(target),
    postMessage(data: unknown, origin: string, transfer: MessagePort[] = []) {
      expect(origin).toBe(ORIGIN);
      const event = Object.assign(new Event("message"), {
        data,
        origin: ORIGIN,
        source: fakeWindow,
        ports: transfer,
      });
      queueMicrotask(() => target.dispatchEvent(event));
    },
  };
  const globals = globalThis as Record<string, unknown>;
  globals.window = fakeWindow;
  Object.defineProperty(globalThis, "navigator", {
    value: { credentials: { get: nativeGet, create: nativeCreate } },
    configurable: true,
  });
  globals.PublicKeyCredential = FakeCredential;
  globals.AuthenticatorAssertionResponse = FakeAssertion;
  globals.AuthenticatorAttestationResponse = FakeAttestation;
  globals.chrome = {
    runtime: {
      id: "ext",
      sendMessage: async (message: Record<string, unknown>) => {
        sent.push(message);
        return { accepted };
      },
      onMessage: { addListener: (listener: Listener) => void listeners.push(listener) },
    },
  };
}

async function requestFor(kind: string): Promise<Record<string, unknown>> {
  await vi.waitFor(() => {
    expect(sent.some((message) => message.kind === kind)).toBe(true);
  });
  return sent.splice(
    sent.findIndex((message) => message.kind === kind),
    1,
  )[0]!;
}

function fromBackground(nonce: unknown, outcome: Record<string, unknown>): void {
  for (const listener of listeners) {
    listener({ kind: "passkey_result", nonce, ...outcome }, { id: "ext" });
  }
}

const GET = { publicKey: { challenge: new Uint8Array([1, 2]), rpId: "example.com" } };

describe("passkey page script and relay", () => {
  beforeAll(async () => {
    installFakes();
    await import("../src/passkey/relay.ts");
    await import("../src/passkey/page.ts");
  });

  it("delivers the vault's assertion to the page as a PublicKeyCredential", async () => {
    const pending = navigator.credentials.get(GET);
    const request = await requestFor("passkey_request");
    expect(request.ceremony).toBe("get");
    expect(request.options).toEqual({
      challenge: "AQI",
      rpId: "example.com",
      allowCredentials: [],
    });
    fromBackground(request.nonce, {
      outcome: "credential",
      credential: {
        id: "BQ",
        rawId: "BQ",
        type: "public-key",
        authenticatorAttachment: "platform",
        response: {
          clientDataJSON: "AQ",
          authenticatorData: "Ag",
          signature: "Aw",
          userHandle: "BA",
        },
        clientExtensionResults: {},
      },
    });
    const credential = (await pending) as PublicKeyCredential;
    expect(credential).toBeInstanceOf(FakeCredential);
    expect(credential.response).toBeInstanceOf(FakeAssertion);
    const response = credential.response as AuthenticatorAssertionResponse;
    expect(new Uint8Array(response.signature)).toEqual(new Uint8Array([3]));
    expect(new Uint8Array(credential.rawId)).toEqual(new Uint8Array([5]));
  });

  it("hands a fallback to the browser's own WebAuthn with the page's options", async () => {
    const pending = navigator.credentials.get(GET);
    const request = await requestFor("passkey_request");
    fromBackground(request.nonce, { outcome: "fallback" });
    expect(await pending).toBe("native get");
    expect(nativeGet).toHaveBeenLastCalledWith(GET);
  });

  it("turns a refusal into the WebAuthn error", async () => {
    const pending = navigator.credentials.create({
      publicKey: {
        rp: { name: "Example" },
        user: { id: new Uint8Array([1]), name: "a", displayName: "A" },
        challenge: new Uint8Array([1]),
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      },
    });
    const request = await requestFor("passkey_request");
    expect(request.ceremony).toBe("create");
    fromBackground(request.nonce, { outcome: "error", error: "invalid_state" });
    await expect(pending).rejects.toMatchObject({ name: "InvalidStateError" });
  });

  it("falls back at once when the extension does not take the request", async () => {
    accepted = false;
    const pending = navigator.credentials.get(GET);
    await requestFor("passkey_request");
    expect(await pending).toBe("native get");
    accepted = true;
  });

  it("an aborted request rejects and cancels in the background, and a late answer is ignored", async () => {
    const abort = new AbortController();
    const pending = navigator.credentials.get({ ...GET, signal: abort.signal });
    const request = await requestFor("passkey_request");
    abort.abort();
    await expect(pending).rejects.toMatchObject({ name: "AbortError" });
    const cancel = await requestFor("passkey_cancel");
    expect(cancel.nonce).toBe(request.nonce);
    fromBackground(request.nonce, { outcome: "fallback" });
  });

  it("leaves conditional mediation and non-WebAuthn requests to the browser", async () => {
    nativeGet.mockClear();
    expect(await navigator.credentials.get({ ...GET, mediation: "conditional" })).toBe(
      "native get",
    );
    expect(await navigator.credentials.get({ password: true } as CredentialRequestOptions)).toBe(
      "native get",
    );
    expect(sent).toEqual([]);
  });
});
