import { describe, expect, it } from "vite-plus/test";
import {
  type AssertionJson,
  decodeAssertion,
  decodeRegistration,
  encodeCreation,
  encodeRequest,
  fromBase64Url,
  type RegistrationJson,
  toBase64Url,
} from "../src/passkey/codec.ts";
import { parseFromPage, parseToPage } from "../src/passkey/bridge.ts";
import { parseToBackground } from "../src/background/router.ts";

const bytes = (...values: number[]) => new Uint8Array(values);
const NO_PROTOTYPES = { credential: undefined, attestation: undefined, assertion: undefined };

describe("passkey codec", () => {
  it("encodes binary members as unpadded base64url from any BufferSource", () => {
    expect(toBase64Url(bytes(0xfb, 0xff, 0xfe))).toBe("-__-");
    expect(toBase64Url(bytes(0xfb, 0xff, 0xfe).buffer)).toBe("-__-");
    const view = new DataView(bytes(9, 1, 2, 9).buffer, 1, 2);
    expect(toBase64Url(view)).toBe("AQI");
    expect(new Uint8Array(fromBase64Url("-__-"))).toEqual(bytes(0xfb, 0xff, 0xfe));
  });

  it("serializes creation options, keeping only numeric algorithms", () => {
    const json = encodeCreation({
      rp: { id: "example.com", name: "Example" },
      user: { id: bytes(1, 2), name: "anne", displayName: "Anne" },
      challenge: bytes(3),
      pubKeyCredParams: [
        { type: "public-key", alg: "-7" as unknown as number },
        { type: "public-key", alg: Number.NaN },
      ],
      excludeCredentials: [{ type: "public-key", id: bytes(4), transports: ["usb"] }],
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      extensions: { credProps: true },
    });
    expect(json).toEqual({
      rp: { id: "example.com", name: "Example" },
      user: { id: "AQI", name: "anne", displayName: "Anne" },
      challenge: "Aw",
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      excludeCredentials: [{ type: "public-key", id: "BA", transports: ["usb"] }],
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      extensions: { credProps: true },
    });
  });

  it("serializes request options without inventing absent members", () => {
    expect(encodeRequest({ challenge: bytes(1), rpId: "example.com" })).toEqual({
      challenge: "AQ",
      rpId: "example.com",
      allowCredentials: [],
    });
  });

  it("rebuilds a registration with the getters SimpleWebAuthn calls", () => {
    const json: RegistrationJson = {
      id: "AQ",
      rawId: "AQ",
      type: "public-key",
      authenticatorAttachment: "platform",
      response: {
        clientDataJSON: "Ag",
        attestationObject: "Aw",
        authenticatorData: "BA",
        publicKey: "BQ",
        publicKeyAlgorithm: -7,
        transports: ["internal", "hybrid"],
      },
      clientExtensionResults: { credProps: { rk: true } },
    };
    const credential = decodeRegistration(json, NO_PROTOTYPES);
    const response = credential.response as AuthenticatorAttestationResponse;
    expect(new Uint8Array(credential.rawId)).toEqual(bytes(1));
    expect(new Uint8Array(response.attestationObject)).toEqual(bytes(3));
    expect(new Uint8Array(response.getAuthenticatorData())).toEqual(bytes(4));
    expect(new Uint8Array(response.getPublicKey() as ArrayBuffer)).toEqual(bytes(5));
    expect(response.getPublicKeyAlgorithm()).toBe(-7);
    expect(response.getTransports()).toEqual(["internal", "hybrid"]);
    expect(credential.getClientExtensionResults()).toEqual({ credProps: { rk: true } });
    expect(credential.toJSON()).toEqual(json);
  });

  it("rebuilds an assertion on the native prototypes it is given", () => {
    class Credential {}
    class Assertion {}
    const json: AssertionJson = {
      id: "AQ",
      rawId: "AQ",
      type: "public-key",
      authenticatorAttachment: "platform",
      response: {
        clientDataJSON: "Ag",
        authenticatorData: "Aw",
        signature: "BA",
        userHandle: null,
      },
      clientExtensionResults: {},
    };
    const credential = decodeAssertion(json, {
      credential: Credential.prototype,
      attestation: undefined,
      assertion: Assertion.prototype,
    });
    expect(credential).toBeInstanceOf(Credential);
    expect(credential.response).toBeInstanceOf(Assertion);
    const response = credential.response as AuthenticatorAssertionResponse;
    expect(new Uint8Array(response.signature)).toEqual(bytes(4));
    expect(response.userHandle).toBeNull();
  });
});

describe("passkey bridge messages", () => {
  it("accepts only well-formed messages on its channel", () => {
    const request = {
      channel: "vaultkeeper-passkey",
      direction: "request",
      id: "r1",
      ceremony: "get",
      options: { challenge: "AQ" },
    };
    expect(parseFromPage(request)).toEqual(request);
    expect(parseFromPage({ ...request, channel: "other" })).toBeNull();
    expect(parseFromPage({ ...request, ceremony: "delete" })).toBeNull();
    expect(parseFromPage({ ...request, id: "x".repeat(65) })).toBeNull();
    expect(
      parseToPage({
        channel: "vaultkeeper-passkey",
        direction: "reply",
        id: "r1",
        outcome: "error",
        error: "boom",
      }),
    ).toBeNull();
    expect(
      parseToPage({
        channel: "vaultkeeper-passkey",
        direction: "reply",
        id: "r1",
        outcome: "fallback",
      }),
    ).toEqual({
      channel: "vaultkeeper-passkey",
      direction: "reply",
      id: "r1",
      outcome: "fallback",
    });
  });

  it("the background parses passkey requests and drops any origin in the body", () => {
    expect(
      parseToBackground({
        kind: "passkey_request",
        nonce: "n",
        ceremony: "create",
        options: { rp: {} },
        origin: "https://evil.example",
      }),
    ).toEqual({ kind: "passkey_request", nonce: "n", ceremony: "create", options: { rp: {} } });
    expect(
      parseToBackground({ kind: "passkey_request", nonce: "n", ceremony: "get", options: null }),
    ).toBeNull();
    expect(parseToBackground({ kind: "passkey_cancel", nonce: "" })).toBeNull();
  });
});
