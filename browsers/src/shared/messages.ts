// Messages between content scripts and the background (BROWSERS.md section 10.3).
// The background computes the origin itself; no message carries one.

export type ErrorCode =
  | "bad_request"
  | "unknown_type"
  | "unpaired"
  | "denied"
  | "cancelled"
  | "timeout"
  | "locked"
  | "logged_out"
  | "no_login"
  | "busy"
  | "rate_limited"
  | "insecure_page"
  | "offline"
  | "internal"
  | "fallback"
  | "not_allowed"
  | "invalid_state";

export type Theme = "light" | "dark" | "system";

export interface FillFields {
  username: boolean;
  password: boolean;
}

/** How a passkey request ended, see src/passkey/bridge.ts. */
export type PasskeyOutcome =
  | { outcome: "credential"; credential: object }
  | { outcome: "fallback" }
  | { outcome: "error"; error: "not_allowed" | "invalid_state" };

/** content -> background */
export type ToBackground =
  | { kind: "passkey_request"; nonce: string; ceremony: "create" | "get"; options: object }
  | { kind: "passkey_cancel"; nonce: string }
  | { kind: "fill_request"; nonce: string; choose: boolean; fields: FillFields; path: string }
  | {
      kind: "save_candidate";
      username: string;
      password: string;
      candidate: "login" | "change";
      path: string;
    };

/** background -> content (tabs.sendMessage) */
export type ToContent =
  | {
      kind: "fill_result";
      nonce: string;
      username: string | null;
      password: string | null;
      theme: Theme;
    }
  | { kind: "fill_error"; nonce: string; code: ErrorCode | "unavailable"; theme: Theme }
  | ({ kind: "passkey_result"; nonce: string } & PasskeyOutcome)
  | { kind: "begin_fill"; choose: boolean }
  | { kind: "theme"; theme: Theme };
