import type { PopupStatus } from "../shared/popup.ts";
import type { RequestMap, RequestType, Theme } from "../shared/protocol.ts";
import { NativeError, type NativeClient } from "./native.ts";
import { exportPublicKey, fingerprint, fromBase64, signProof, toBase64 } from "./pairing.ts";

export interface SessionDeps {
  native: NativeClient;
  keys(): Promise<CryptoKeyPair>;
  caller: string;
  extensionVersion: string;
  onChange(status: PopupStatus): void;
}

const INITIAL: PopupStatus = {
  phase: "idle",
  state: null,
  theme: "system",
  fingerprint: null,
  reason: null,
};

export class Session {
  #status: PopupStatus = INITIAL;
  #handshake: Promise<void> | null = null;
  readonly #deps: SessionDeps;

  constructor(deps: SessionDeps) {
    this.#deps = deps;
    deps.native.onEvent((event) => {
      if (event.event === "state") {
        this.#set({ state: event.state, theme: event.theme });
      } else if (event.event === "unavailable") {
        this.#set({ phase: "unavailable", state: null, reason: event.reason });
      }
    });
  }

  get status(): PopupStatus {
    return this.#status;
  }

  get theme(): Theme {
    return this.#status.theme;
  }

  /** Connects and pairs when needed. Safe to call from every user action. */
  ensureReady(): Promise<void> {
    if (this.#status.phase === "ready" && this.#deps.native.connected) {
      return Promise.resolve();
    }
    this.#handshake ??= this.#runHandshake().finally(() => {
      this.#handshake = null;
    });
    return this.#handshake;
  }

  async request<T extends RequestType>(
    type: T,
    fields: RequestMap[T]["fields"],
  ): Promise<RequestMap[T]["result"]> {
    await this.ensureReady();
    return this.#deps.native.request(type, fields);
  }

  async #runHandshake(): Promise<void> {
    const { native } = this.#deps;
    this.#set({ phase: "connecting", reason: null });
    try {
      const pair = await this.#deps.keys();
      const publicKey = await exportPublicKey(pair);
      const print = await fingerprint(publicKey);
      this.#set({ fingerprint: print });
      const hello = await native.request("hello", {
        protocol: 1,
        extension_version: this.#deps.extensionVersion,
        public_key: toBase64(publicKey),
      });
      if (!hello.known) {
        this.#set({ phase: "pairing" });
      }
      const signature = await signProof(pair, fromBase64(hello.challenge), this.#deps.caller);
      const proof = await native.request("prove", { signature: toBase64(signature) });
      this.#set({ phase: "ready", state: proof.state, theme: proof.theme, reason: null });
    } catch (error) {
      this.#fail(error);
      throw error;
    }
  }

  #fail(error: unknown): void {
    if (error instanceof NativeError) {
      if (error.code === "unavailable") {
        this.#set({ phase: "unavailable", state: null, reason: error.reason ?? "disconnected" });
      } else if (error.code === "denied" || error.code === "unpaired") {
        this.#deps.native.disconnect();
        this.#set({ phase: "denied", state: null, reason: error.code });
      } else {
        this.#set({ phase: "error", state: null, reason: error.code });
      }
      return;
    }
    this.#set({ phase: "error", state: null, reason: "internal" });
  }

  #set(patch: Partial<PopupStatus>): void {
    this.#status = { ...this.#status, ...patch };
    this.#deps.onChange(this.#status);
  }
}
