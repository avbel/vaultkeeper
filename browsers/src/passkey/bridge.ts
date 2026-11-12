// Messages between the page script (the page's world) and the relay (the extension's isolated
// world) of one frame. A request goes by window.postMessage and carries a MessagePort; the answer
// and a cancel travel on that port. Firefox does not give a message the relay posts to the window
// the page's own `window` as `event.source`, so answers by window.postMessage would be dropped.
// The page can read and forge all of this: it carries only what the page itself passed to or gets
// from navigator.credentials.

import type { AssertionJson, JsonObject, RegistrationJson } from "./codec.ts";

export const CHANNEL = "vaultkeeper-passkey";

export type Ceremony = "create" | "get";

/** How a request ended: the vault's credential, the browser's own WebAuthn, or an error. */
export type Outcome =
  | { outcome: "credential"; credential: RegistrationJson | AssertionJson }
  | { outcome: "fallback" }
  | { outcome: "error"; error: "not_allowed" | "invalid_state" };

/** Posted to the window with the request's port. */
export interface PageRequest {
  channel: typeof CHANNEL;
  id: string;
  ceremony: Ceremony;
  options: JsonObject;
}

/** Sent by the page on the request's port when the page gives up. */
export const CANCEL = "cancel";

const MAX_ID = 64;

export function parseRequest(data: unknown): PageRequest | null {
  if (typeof data !== "object" || data === null) {
    return null;
  }
  const m = data as Record<string, unknown>;
  if (
    m.channel !== CHANNEL ||
    typeof m.id !== "string" ||
    m.id.length === 0 ||
    m.id.length > MAX_ID ||
    (m.ceremony !== "create" && m.ceremony !== "get") ||
    typeof m.options !== "object" ||
    m.options === null
  ) {
    return null;
  }
  return {
    channel: CHANNEL,
    id: m.id,
    ceremony: m.ceremony,
    options: m.options as JsonObject,
  };
}

export function parseOutcome(data: unknown): Outcome | null {
  if (typeof data !== "object" || data === null) {
    return null;
  }
  const m = data as Record<string, unknown>;
  if (m.outcome === "credential" && typeof m.credential === "object" && m.credential !== null) {
    return { outcome: "credential", credential: m.credential as RegistrationJson | AssertionJson };
  }
  if (m.outcome === "fallback") {
    return { outcome: "fallback" };
  }
  if (m.outcome === "error" && (m.error === "not_allowed" || m.error === "invalid_state")) {
    return { outcome: "error", error: m.error };
  }
  return null;
}
