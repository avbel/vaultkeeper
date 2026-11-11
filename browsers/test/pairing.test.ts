import { beforeEach, describe, expect, it } from "vite-plus/test";
import {
  callerString,
  exportPublicKey,
  fingerprint,
  fromBase64,
  getOrCreateKeyPair,
  proofMessage,
  resetKeyPairCache,
  signProof,
  toBase64,
  type KeyStore,
} from "../src/background/pairing.ts";

function memoryStore(): KeyStore & { saved: number } {
  let pair: CryptoKeyPair | undefined;
  const store = {
    saved: 0,
    async load() {
      return pair;
    },
    async save(next: CryptoKeyPair) {
      pair = next;
      store.saved += 1;
    },
  };
  return store;
}

beforeEach(() => {
  resetKeyPairCache();
});

describe("pairing key", () => {
  it("is generated once, non-extractable, and reused", async () => {
    const store = memoryStore();
    const first = await getOrCreateKeyPair(store);
    resetKeyPairCache();
    const second = await getOrCreateKeyPair(store);
    expect(store.saved).toBe(1);
    expect(second).toBe(first);
    expect(first.privateKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey("pkcs8", first.privateKey)).rejects.toThrow();
  });

  it("concurrent first uses share one key", async () => {
    const store = memoryStore();
    const [a, b] = await Promise.all([getOrCreateKeyPair(store), getOrCreateKeyPair(store)]);
    expect(a).toBe(b);
    expect(store.saved).toBe(1);
  });

  it("exports a 65-byte uncompressed point", async () => {
    const pair = await getOrCreateKeyPair(memoryStore());
    const raw = await exportPublicKey(pair);
    expect(raw).toHaveLength(65);
    expect(raw[0]).toBe(0x04);
  });
});

describe("proof signature", () => {
  it("is 64 bytes and verifies against the exported public key", async () => {
    const pair = await getOrCreateKeyPair(memoryStore());
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const caller = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/";
    const signature = await signProof(pair, challenge, caller);
    expect(signature).toHaveLength(64);

    const publicKey = await crypto.subtle.importKey(
      "raw",
      (await exportPublicKey(pair)) as BufferSource,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const verify = (message: Uint8Array) =>
      crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        publicKey,
        signature as BufferSource,
        message as BufferSource,
      );
    expect(await verify(proofMessage(challenge, caller))).toBe(true);
    expect(await verify(proofMessage(challenge, "chrome-extension://other/"))).toBe(false);
  });

  it("signs prefix, raw challenge and UTF-8 caller in that order", () => {
    const message = proofMessage(new Uint8Array([1, 2, 3]), "é");
    const prefix = new TextEncoder().encode("vaultkeeper-browser-v1\0");
    expect([...message.subarray(0, prefix.length)]).toEqual([...prefix]);
    expect([...message.subarray(prefix.length)]).toEqual([1, 2, 3, 0xc3, 0xa9]);
  });
});

describe("fingerprint", () => {
  it("has four uppercase hex groups of four", async () => {
    const pair = await getOrCreateKeyPair(memoryStore());
    expect(await fingerprint(await exportPublicKey(pair))).toMatch(
      /^[0-9A-F]{4}(-[0-9A-F]{4}){3}$/,
    );
  });

  it("is the first 8 bytes of SHA-256 of the key", async () => {
    const key = new Uint8Array(65).fill(7);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", key));
    const hex = [...digest.subarray(0, 8)]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
      .toUpperCase();
    expect(await fingerprint(key)).toBe(hex.replace(/(.{4})(?=.)/g, "$1-"));
  });
});

describe("base64 and caller", () => {
  it("round-trips bytes", () => {
    const bytes = Uint8Array.from({ length: 256 }, (_, i) => i);
    expect([...fromBase64(toBase64(bytes))]).toEqual([...bytes]);
  });

  it("uses the origin form in Chrome and the add-on id in Firefox", () => {
    expect(callerString({ id: "abc", getURL: (p) => `chrome-extension://abc${p}` })).toBe(
      "chrome-extension://abc/",
    );
    expect(
      callerString({
        id: "browser-extension@vaultkeeper",
        getURL: (p) => `moz-extension://uuid${p}`,
      }),
    ).toBe("browser-extension@vaultkeeper");
  });
});
