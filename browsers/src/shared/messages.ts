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
  | "internal";

export type Theme = "light" | "dark" | "system";

export interface FillFields {
  username: boolean;
  password: boolean;
}

/** content -> background */
export type ToBackground =
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
  | { kind: "begin_fill"; choose: boolean }
  | { kind: "theme"; theme: Theme };
