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
  /** `auto`: started by the page opening; it fills only fields that are visible and still empty. */
  request: (form: LoginForm, choose: boolean, auto?: boolean) => boolean;
  applyResult: (message: FillResultMessage) => FillOutcome;
  applyError: (message: FillErrorMessage) => boolean;
  cancel: () => void;
  isPending: () => boolean;
}

export interface FillOutcome {
  claimed: boolean;
  filled: number;
  /** The request was an automatic one: a result that fills nothing is not worth a message. */
  auto: boolean;
}

interface Pending {
  nonce: string;
  origin: string;
  createdAt: number;
  auto: boolean;
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
  const blank = (el: HTMLInputElement | undefined): el is HTMLInputElement =>
    el !== undefined && visible(el) && el.value === "";

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

  // An automatic fill never overwrites: the user may have started typing since the request.
  const write = (p: Pending, el: HTMLInputElement | undefined, value: string | null): number => {
    if (!el || value === null || !visible(el) || (p.auto && el.value !== "")) {
      return 0;
    }
    setNativeValue(el, value);
    deps.onFilled?.(el);
    return 1;
  };

  return {
    request(form, choose, auto = false) {
      // A click supersedes an automatic request still waiting for its answer.
      if (pending && live(pending) && !pending.auto) {
        return false;
      }
      const fields = auto
        ? { username: blank(form.username), password: blank(form.password) }
        : { username: form.username !== undefined, password: form.password !== undefined };
      if (auto ? !fields.password : !fields.username && !fields.password) {
        return false;
      }
      const created: Pending = {
        nonce: randomNonce(),
        origin: origin(),
        createdAt: now(),
        auto,
        passwordWasNew: form.password ? isNewPassword(form.password) : false,
      };
      if (form.username && fields.username) {
        created.username = form.username;
      }
      if (form.password && fields.password) {
        created.password = form.password;
      }
      pending = created;
      deps.send({ kind: "fill_request", nonce: created.nonce, choose, auto, fields, path: path() });
      return true;
    },

    applyResult(message) {
      const p = claim(message.nonce);
      if (!p) {
        return { claimed: false, filled: 0, auto: false };
      }
      const username = p.username && !isPasswordField(p.username) ? p.username : undefined;
      const password =
        p.password &&
        isPasswordField(p.password) &&
        (p.passwordWasNew || !isNewPassword(p.password))
          ? p.password
          : undefined;
      const filled = write(p, username, message.username) + write(p, password, message.password);
      return { claimed: true, filled, auto: p.auto };
    },

    applyError(message) {
      return claim(message.nonce) !== null;
    },

    cancel() {
      pending = null;
    },

    isPending() {
      return pending !== null && live(pending) && !pending.auto;
    },
  };
}
