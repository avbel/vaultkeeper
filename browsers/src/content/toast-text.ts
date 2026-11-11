import type { ToContent } from "../shared/messages.ts";

export const TOAST = {
  locked: "Vaultkeeper is locked",
  noLogin: "No login chosen",
  notRunning: "Vaultkeeper is not running",
  totpCopied: "TOTP code copied",
  noForm: "No login form found on this page",
  generic: "Vaultkeeper could not fill this page",
} as const;

type FillErrorCode = Extract<ToContent, { kind: "fill_error" }>["code"];

export function toastForError(code: FillErrorCode): string {
  switch (code) {
    case "locked":
    case "logged_out":
      return TOAST.locked;
    case "cancelled":
    case "denied":
    case "no_login":
      return TOAST.noLogin;
    case "unavailable":
    case "offline":
      return TOAST.notRunning;
    default:
      return TOAST.generic;
  }
}
