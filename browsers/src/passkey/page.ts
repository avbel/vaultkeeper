// Runs in the page's own world at document_start, before the page's scripts: offers the vault's
// passkeys for navigator.credentials.create/get and hands every request the vault does not take
// to the browser's own WebAuthn, untouched.

import { CHANNEL, type Ceremony, type FromPage, type Outcome, parseToPage } from "./bridge.ts";
import {
  type AssertionJson,
  decodeAssertion,
  decodeRegistration,
  encodeCreation,
  encodeRequest,
  type JsonObject,
  type Prototypes,
  type RegistrationJson,
} from "./codec.ts";

/** A request the extension never answers (it was reloaded) goes to the browser after this. */
const NO_ANSWER_MS = 300_000;

function install(): void {
  const credentials = globalThis.navigator?.credentials;
  if (!credentials || typeof globalThis.PublicKeyCredential === "undefined") {
    return;
  }
  const nativeCreate = credentials.create.bind(credentials);
  const nativeGet = credentials.get.bind(credentials);
  const prototypes: Prototypes = {
    credential: PublicKeyCredential.prototype,
    attestation: globalThis.AuthenticatorAttestationResponse?.prototype,
    assertion: globalThis.AuthenticatorAssertionResponse?.prototype,
  };
  const waiting = new Map<string, (outcome: Outcome) => void>();

  window.addEventListener("message", (event: MessageEvent) => {
    if (event.source !== window) {
      return;
    }
    const reply = parseToPage(event.data);
    if (reply) {
      waiting.get(reply.id)?.(reply);
    }
  });

  const post = (message: FromPage): void => {
    window.postMessage(message, window.location.origin);
  };

  function ask(
    ceremony: Ceremony,
    options: JsonObject,
    signal: AbortSignal | undefined,
  ): Promise<Outcome> {
    if (signal?.aborted) {
      return Promise.reject(
        signal.reason ?? new DOMException("The operation was aborted.", "AbortError"),
      );
    }
    const id = crypto.randomUUID();
    return new Promise<Outcome>((resolve, reject) => {
      const giveUp = setTimeout(() => {
        finish({ outcome: "fallback" });
        post({ channel: CHANNEL, direction: "cancel", id });
      }, NO_ANSWER_MS);
      const onAbort = (): void => {
        clearTimeout(giveUp);
        waiting.delete(id);
        post({ channel: CHANNEL, direction: "cancel", id });
        reject(signal?.reason ?? new DOMException("The operation was aborted.", "AbortError"));
      };
      const finish = (outcome: Outcome): void => {
        clearTimeout(giveUp);
        waiting.delete(id);
        signal?.removeEventListener("abort", onAbort);
        resolve(outcome);
      };
      signal?.addEventListener("abort", onAbort, { once: true });
      waiting.set(id, finish);
      post({ channel: CHANNEL, direction: "request", id, ceremony, options });
    });
  }

  function refused(outcome: Extract<Outcome, { outcome: "error" }>): DOMException {
    return outcome.error === "invalid_state"
      ? new DOMException(
          "The authenticator already holds a credential for this account.",
          "InvalidStateError",
        )
      : new DOMException("The operation either timed out or was not allowed.", "NotAllowedError");
  }

  credentials.create = async (options?: CredentialCreationOptions): Promise<Credential | null> => {
    if (!options?.publicKey) {
      return nativeCreate(options);
    }
    let encoded: JsonObject;
    try {
      encoded = encodeCreation(options.publicKey);
    } catch {
      return nativeCreate(options);
    }
    const outcome = await ask("create", encoded, options.signal);
    switch (outcome.outcome) {
      case "credential":
        return decodeRegistration(outcome.credential as RegistrationJson, prototypes);
      case "fallback":
        return nativeCreate(options);
      case "error":
        throw refused(outcome);
    }
  };

  credentials.get = async (options?: CredentialRequestOptions): Promise<Credential | null> => {
    // Conditional (autofill) requests stay with the browser in this version.
    if (!options?.publicKey || options.mediation === "conditional") {
      return nativeGet(options);
    }
    let encoded: JsonObject;
    try {
      encoded = encodeRequest(options.publicKey);
    } catch {
      return nativeGet(options);
    }
    const outcome = await ask("get", encoded, options.signal);
    switch (outcome.outcome) {
      case "credential":
        return decodeAssertion(outcome.credential as AssertionJson, prototypes);
      case "fallback":
        return nativeGet(options);
      case "error":
        throw refused(outcome);
    }
  };
}

install();
