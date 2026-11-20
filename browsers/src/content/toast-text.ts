import type { ToContent } from "../shared/messages.ts";

export const TOAST = {
  locked: "Vaultkeeper is locked",
  noLogin: "No login chosen",
  notRunning: "Vaultkeeper is not running",
  totpCopied: "TOTP code copied",
  noForm: "No login form found on this page",
  generic: "Vaultkeeper could not fill this page",
  generated: "Strong password filled. Vaultkeeper will offer to save it when you submit",
  generatedPrivate:
    "Strong password filled. Private windows are not saved: find it in Vaultkeeper's Generator",
  generatedChanged:
    "The page changed the generated password. Vaultkeeper keeps the original in its Generator",
  fieldTooShort: "This field is too short for a strong password",
  insecureGenerate: "Vaultkeeper generates passwords only on secure pages",
  updateApp: "Update the Vaultkeeper app to generate passwords",
  generateFailed: "Vaultkeeper could not generate a password",
} as const;

export const MENU = {
  generate: "Use a strong password",
  generateLabel: "Generate a password with Vaultkeeper",
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

type GenerateErrorCode = Extract<ToContent, { kind: "generate_error" }>["code"];

export function toastForGenerateError(code: GenerateErrorCode): string {
  switch (code) {
    case "locked":
    case "logged_out":
      return TOAST.locked;
    case "unavailable":
    case "offline":
      return TOAST.notRunning;
    case "insecure_page":
      return TOAST.insecureGenerate;
    case "unknown_type":
      return TOAST.updateApp;
    default:
      return TOAST.generateFailed;
  }
}
