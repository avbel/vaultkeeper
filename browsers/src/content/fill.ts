import type { ToBackground, ToContent } from "../shared/messages.ts";
import { autocompleteTokens, isPasswordField, isVisible, type LoginForm } from "./detect.ts";

export const NONCE_TTL_MS = 130_000;

type FillResultMessage = Extract<ToContent, { kind: "fill_result" }>;
type FillErrorMessage = Extract<ToContent, { kind: "fill_error" }>;

export interface FillDeps {
  send: (message: ToBackground) => void;
  onFilled?: (el: HTMLInputElement) => void;
  isVisible?: (el: HTMLInputElement) => boolean;
  now?: () => number;
  origin?: () => string;
  path?: () => string;
}

export interface Filler {
  request: (form: LoginForm, choose: boolean) => boolean;
  applyResult: (message: FillResultMessage) => FillOutcome;
  applyError: (message: FillErrorMessage) => boolean;
  cancel: () => void;
  isPending: () => boolean;
}

export interface FillOutcome {
  claimed: boolean;
  filled: number;
}

interface Pending {
  nonce: string;
  origin: string;
  createdAt: number;
  username?: HTMLInputElement;
  password?: HTMLInputElement;
  // Detection already accepted a sign-in field tagged new-password; only a token added later
  // means the page turned the field into a new-password one.
  passwordWasNew: boolean;
}

function isNewPassword(el: HTMLInputElement): boolean {
  return autocompleteTokens(el).has("new-password");
}

function randomNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// The page can shadow the `value` property of an element; the prototype setter writes the real value
// and is what frameworks that track values (React) observe.
export function setNativeValue(el: HTMLInputElement, value: string): void {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  if (!setter) {
    return;
  }
  setter.call(el, value);
  el.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
}

export function createFiller(deps: FillDeps): Filler {
  const visible = deps.isVisible ?? isVisible;
  const now = deps.now ?? (() => Date.now());
  const origin = deps.origin ?? (() => location.origin);
  const path = deps.path ?? (() => location.pathname);
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

  const write = (el: HTMLInputElement | undefined, value: string | null): number => {
    if (!el || value === null || !visible(el)) {
      return 0;
    }
    setNativeValue(el, value);
    deps.onFilled?.(el);
    return 1;
  };

  return {
    request(form, choose) {
      if (pending && live(pending)) {
        return false;
      }
      const fields = {
        username: form.username !== undefined,
        password: form.password !== undefined,
      };
      if (!fields.username && !fields.password) {
        return false;
      }
      const created: Pending = {
        nonce: randomNonce(),
        origin: origin(),
        createdAt: now(),
        passwordWasNew: form.password ? isNewPassword(form.password) : false,
      };
      if (form.username) {
        created.username = form.username;
      }
      if (form.password) {
        created.password = form.password;
      }
      pending = created;
      deps.send({ kind: "fill_request", nonce: created.nonce, choose, fields, path: path() });
      return true;
    },

    applyResult(message) {
      const p = claim(message.nonce);
      if (!p) {
        return { claimed: false, filled: 0 };
      }
      const username = p.username && !isPasswordField(p.username) ? p.username : undefined;
      const password =
        p.password &&
        isPasswordField(p.password) &&
        (p.passwordWasNew || !isNewPassword(p.password))
          ? p.password
          : undefined;
      const filled = write(username, message.username) + write(password, message.password);
      return { claimed: true, filled };
    },

    applyError(message) {
      return claim(message.nonce) !== null;
    },

    cancel() {
      pending = null;
    },

    isPending() {
      return pending !== null && live(pending);
    },
  };
}
