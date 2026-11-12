// Wire types of BROWSERS.md section 3.3 (extension <-> daemon, relayed by the native host).
import type { ErrorCode, Theme } from "./messages.ts";

export type { ErrorCode, Theme };

export type VaultState = "unlocked" | "locked" | "logged_out";

export interface RequestMap {
  hello: {
    fields: { protocol: 1; extension_version: string; public_key: string };
    result: { challenge: string; known: boolean };
  };
  prove: {
    fields: { signature: string };
    result: { state: VaultState; theme: Theme; fingerprint: string };
  };
  status: {
    fields: Record<string, never>;
    result: { state: VaultState; theme: Theme };
  };
  fill: {
    fields: {
      origin: string;
      path: string;
      choose: boolean;
      fields: { username: boolean; password: boolean };
    };
    result: { username: string | null; password: string | null };
  };
  save_candidate: {
    fields: {
      origin: string;
      path: string;
      username: string;
      password: string;
      kind: "login" | "change";
    };
    result: Record<string, never>;
  };
  unlock: {
    fields: Record<string, never>;
    result: { state: VaultState };
  };
  open_app: {
    fields: { view: "manager" | "settings" };
    result: Record<string, never>;
  };
  passkey_create: {
    fields: { origin: string; options: object };
    result: { credential: object };
  };
  passkey_get: {
    fields: { origin: string; options: object };
    result: { credential: object };
  };
  passkey_cancel: {
    fields: { origin: string };
    result: Record<string, never>;
  };
}

export type RequestType = keyof RequestMap;

export interface SuccessResponse {
  id: number;
  ok: true;
  result: unknown;
}

export interface FailureResponse {
  id: number;
  ok: false;
  error: ErrorCode;
}

export type Response = SuccessResponse | FailureResponse;

export type NativeEvent =
  | { event: "state"; state: VaultState; theme: Theme }
  | { event: "unavailable"; reason: string }
  | { event: "ping" };

export const NATIVE_REQUEST_TIMEOUT_MS = 130_000;
