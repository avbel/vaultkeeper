// Messages between the page script (the page's world) and the relay (the extension's isolated
// world) of one frame. They travel by window.postMessage, so the page can read and forge them:
// they carry only what the page itself passed to or gets from navigator.credentials.

import type { AssertionJson, JsonObject, RegistrationJson } from "./codec.ts";

export const CHANNEL = "vaultkeeper-passkey";

export type Ceremony = "create" | "get";

/** How a request ended: the vault's credential, the browser's own WebAuthn, or an error. */
export type Outcome =
  | { outcome: "credential"; credential: RegistrationJson | AssertionJson }
  | { outcome: "fallback" }
  | { outcome: "error"; error: "not_allowed" | "invalid_state" };

export type FromPage =
  | {
      channel: typeof CHANNEL;
      direction: "request";
      id: string;
      ceremony: Ceremony;
      options: JsonObject;
    }
  | { channel: typeof CHANNEL; direction: "cancel"; id: string };

export type ToPage = { channel: typeof CHANNEL; direction: "reply"; id: string } & Outcome;

const MAX_ID = 64;

export function parseFromPage(data: unknown): FromPage | null {
  if (typeof data !== "object" || data === null) {
    return null;
  }
  const m = data as Record<string, unknown>;
  if (
    m.channel !== CHANNEL ||
    typeof m.id !== "string" ||
    m.id.length === 0 ||
    m.id.length > MAX_ID
  ) {
    return null;
  }
  if (m.direction === "cancel") {
    return { channel: CHANNEL, direction: "cancel", id: m.id };
  }
  if (
    m.direction === "request" &&
    (m.ceremony === "create" || m.ceremony === "get") &&
    typeof m.options === "object" &&
    m.options !== null
  ) {
    return {
      channel: CHANNEL,
      direction: "request",
      id: m.id,
      ceremony: m.ceremony,
      options: m.options as JsonObject,
    };
  }
  return null;
}

export function parseToPage(data: unknown): ToPage | null {
  if (typeof data !== "object" || data === null) {
    return null;
  }
  const m = data as Record<string, unknown>;
  if (m.channel !== CHANNEL || m.direction !== "reply" || typeof m.id !== "string") {
    return null;
  }
  if (m.outcome === "credential" && typeof m.credential === "object" && m.credential !== null) {
    return m as unknown as ToPage;
  }
  if (m.outcome === "fallback") {
    return { channel: CHANNEL, direction: "reply", id: m.id, outcome: "fallback" };
  }
  if (m.outcome === "error" && (m.error === "not_allowed" || m.error === "invalid_state")) {
    return { channel: CHANNEL, direction: "reply", id: m.id, outcome: "error", error: m.error };
  }
  return null;
}
