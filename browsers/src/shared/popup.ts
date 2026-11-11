import type { Theme, VaultState } from "./protocol.ts";

export type Phase =
  | "idle"
  | "connecting"
  | "pairing"
  | "ready"
  | "unavailable"
  | "denied"
  | "error";

export interface PopupStatus {
  phase: Phase;
  state: VaultState | null;
  theme: Theme;
  fingerprint: string | null;
  reason: string | null;
}

/** popup -> background */
export type PopupRequest =
  | { kind: "popup_status" }
  | { kind: "popup_fill"; choose: boolean }
  | { kind: "popup_unlock" }
  | { kind: "popup_open_app"; view: "manager" | "settings" };

/** background -> popup, pushed with runtime.sendMessage */
export interface PopupPush {
  kind: "popup_status_changed";
  status: PopupStatus;
}

export const POPUP_KINDS: readonly string[] = [
  "popup_status",
  "popup_fill",
  "popup_unlock",
  "popup_open_app",
];

export type PopupFillReply = { ok: true; found: boolean } | { ok: false; reason: "unreachable" };
