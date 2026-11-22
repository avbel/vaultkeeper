import type { FieldLimits, ToBackground, ToContent } from "../shared/messages.ts";
import { isVisible, type LoginForm } from "./detect.ts";
import { NONCE_TTL_MS, setNativeValue } from "./fill.ts";

/** Shorter fields cannot hold a strong password; the app refuses them too. */
const MIN_STRONG_LENGTH = 5;

type ResultMessage = Extract<ToContent, { kind: "generate_result" }>;
type ErrorMessage = Extract<ToContent, { kind: "generate_error" }>;

export type GenerateOutcome = "filled" | "changed" | "ignored";
export type GenerateRequest = "sent" | "too_short" | "pending";

export interface GeneratorDeps {
  send: (message: ToBackground) => void;
  /** Every field now holds `value` exactly as generated. */
  onGenerated: (form: LoginForm, fields: HTMLInputElement[], value: string) => void;
  isVisible?: (el: HTMLInputElement) => boolean;
  now?: () => number;
  origin?: () => string;
}

export interface Generator {
  /** `anchor` is the field the menu was opened on; it is filled even when it holds text. */
  request: (form: LoginForm, anchor: HTMLInputElement) => GenerateRequest;
  applyResult: (message: ResultMessage) => GenerateOutcome;
  applyError: (message: ErrorMessage) => boolean;
  /** Drops the pending request with `nonce`; true when it was still pending. */
  cancel: (nonce: string) => boolean;
}

interface Pending {
  nonce: string;
  origin: string;
  createdAt: number;
  form: LoginForm;
  anchor: HTMLInputElement;
}

function randomNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// `minLength`/`maxLength` are -1 when the page sets none. The password and its confirmation
// must both accept it, so the tightest of each wins.
export function fieldLimits(fields: HTMLInputElement[]): FieldLimits {
  const mins = fields.map((el) => el.minLength).filter((n) => n > 0);
  const maxes = fields.map((el) => el.maxLength).filter((n) => n > 0);
  return {
    min_length: mins.length > 0 ? Math.max(...mins) : null,
    max_length: maxes.length > 0 ? Math.min(...maxes) : null,
  };
}

export function createGenerator(deps: GeneratorDeps): Generator {
  const visible = deps.isVisible ?? isVisible;
  const now = deps.now ?? (() => Date.now());
  const origin = deps.origin ?? (() => location.origin);
  let pending: Pending | null = null;

  const live = (p: Pending): boolean => now() - p.createdAt < NONCE_TTL_MS;

  const claim = (nonce: string): Pending | null => {
    const current = pending;
    if (!current || current.nonce !== nonce) {
      return null;
    }
    pending = null;
    if (!live(current) || origin() !== current.origin) {
      return null;
    }
    return current;
  };

  return {
    request(form, anchor) {
      // The first may be waiting for an unlock; its answer must still find its fields.
      if (pending && live(pending)) {
        return "pending";
      }
      const limits = fieldLimits(form.newPasswords);
      if (limits.max_length !== null && limits.max_length < MIN_STRONG_LENGTH) {
        return "too_short";
      }
      const created: Pending = {
        nonce: randomNonce(),
        origin: origin(),
        createdAt: now(),
        form,
        anchor,
      };
      pending = created;
      deps.send({ kind: "generate_request", nonce: created.nonce, limits });
      return "sent";
    },

    applyResult(message) {
      const p = claim(message.nonce);
      if (!p) {
        return "ignored";
      }
      // A field that already holds text may be the current password of a form that names
      // neither field, so only the chosen field and empty ones are written.
      const fields = p.form.newPasswords.filter(
        (el) => el.isConnected && visible(el) && (el === p.anchor || el.value === ""),
      );
      if (fields.length === 0) {
        return "ignored";
      }
      for (const el of fields) {
        setNativeValue(el, message.password);
      }
      // A page that trims or rewrites the value would have the vault store a password the site
      // never saw; such a fill is not offered for saving.
      if (fields.some((el) => el.value !== message.password)) {
        return "changed";
      }
      deps.onGenerated(p.form, fields, message.password);
      return "filled";
    },

    applyError(message) {
      return claim(message.nonce) !== null;
    },

    cancel(nonce) {
      if (pending?.nonce !== nonce) {
        return false;
      }
      pending = null;
      return true;
    },
  };
}
