import type { LoginForm } from "./detect.ts";
import { composedContains, eventTarget, isInput } from "./dom.ts";
import { applyInput } from "./typed-text.ts";

export interface SaveCandidate {
  username: string;
  password: string;
  candidate: "login" | "change";
  path: string;
}

export interface CaptureDeps {
  forms: () => LoginForm[];
  rescan: () => LoginForm[];
  emit: (candidate: SaveCandidate) => void;
  isTrusted?: (event: Event) => boolean;
  path?: () => string;
  now?: () => number;
}

export interface Capture {
  markFilled: (el: HTMLInputElement) => void;
  refresh: (forms: LoginForm[]) => void;
  dispose: () => void;
}

const SUBMIT_TEXT = /log ?in|sign ?in|continue|next|submit|change|update|save/i;
const MAX_USERNAME = 512;
const MAX_PASSWORD = 4096;
const SUBMIT_INTENT_MS = 2_000;
const INTERACTION_MS = 30_000;

function passwordFields(form: LoginForm): HTMLInputElement[] {
  return [...(form.password ? [form.password] : []), ...form.newPasswords];
}

function isSubmitLike(el: Element): boolean {
  if (el.localName === "input") {
    return (el as HTMLInputElement).type === "submit";
  }
  if (el.localName !== "button") {
    return false;
  }
  const button = el as HTMLButtonElement;
  return button.type === "submit" || SUBMIT_TEXT.test(button.textContent ?? "");
}

export function createCapture(deps: CaptureDeps, doc: Document = document): Capture {
  const trusted = deps.isTrusted ?? ((event: Event) => event.isTrusted);
  const path = deps.path ?? (() => location.pathname);
  const now = deps.now ?? (() => Date.now());
  const model = new Map<HTMLInputElement, string | null>();
  const submitIntent = new WeakMap<Element, number>();
  const interaction = new WeakMap<Element, number>();
  const emitted = new WeakSet<Element>();
  const watched = new WeakSet<Element>();
  let known: LoginForm[] = [];
  let lastUsername = "";

  const typedBy = (el: HTMLInputElement): string | undefined => {
    const text = model.get(el);
    return text && el.value === text ? text : undefined;
  };

  const recent = (map: WeakMap<Element, number>, form: LoginForm, limit: number): boolean => {
    const at = map.get(form.container);
    return at !== undefined && now() - at < limit;
  };

  const candidateFor = (form: LoginForm): SaveCandidate | null => {
    const username = form.username?.value || lastUsername;
    const values = form.newPasswords.map(typedBy).filter((v): v is string => !!v);
    let password: string | undefined;
    let candidate: SaveCandidate["candidate"] = "login";
    if (values.length >= 2 && values.every((v) => v === values[0])) {
      password = values[0];
      candidate = "change";
    } else if (form.password) {
      password = typedBy(form.password);
    } else if (form.newPasswords.length === 1) {
      password = values[0];
    }
    if (!password || password.length > MAX_PASSWORD || username.length > MAX_USERNAME) {
      return null;
    }
    return { username, password, candidate, path: path() };
  };

  const emitFor = (form: LoginForm): void => {
    if (form.username?.value) {
      lastUsername = form.username.value;
    }
    if (emitted.has(form.container)) {
      return;
    }
    const candidate = candidateFor(form);
    if (!candidate) {
      return;
    }
    emitted.add(form.container);
    deps.emit(candidate);
  };

  const formOf = (el: Element): LoginForm | undefined => {
    const match = (forms: LoginForm[]) => forms.find((f) => composedContains(f.container, el));
    return match(deps.forms()) ?? match(deps.rescan());
  };

  const touch = (map: WeakMap<Element, number>, form: LoginForm): void => {
    map.set(form.container, now());
  };

  const watch = (form: LoginForm): void => {
    if (form.container.localName !== "form" || watched.has(form.container)) {
      return;
    }
    watched.add(form.container);
    form.container.addEventListener("submit", () => {
      const current = known.find((f) => f.container === form.container);
      if (current && recent(submitIntent, current, SUBMIT_INTENT_MS)) {
        emitFor(current);
      }
    });
  };

  const onInput = (event: Event): void => {
    const el = eventTarget(event);
    if (!trusted(event) || !isInput(el)) {
      return;
    }
    const form = formOf(el);
    if (!form) {
      return;
    }
    touch(interaction, form);
    if (passwordFields(form).includes(el)) {
      model.set(el, applyInput(model.get(el), event, el.value));
      emitted.delete(form.container);
    } else if (form.username === el) {
      lastUsername = el.value;
    }
  };

  const onKeydown = (event: Event): void => {
    const el = eventTarget(event);
    if (!trusted(event) || !el) {
      return;
    }
    const form = deps.forms().find((f) => composedContains(f.container, el));
    if (!form) {
      return;
    }
    touch(interaction, form);
    if ((event as KeyboardEvent).key !== "Enter") {
      return;
    }
    touch(submitIntent, form);
    if (isInput(el) && passwordFields(form).includes(el)) {
      emitFor(form);
    }
  };

  const onClick = (event: Event): void => {
    const el = eventTarget(event);
    if (!trusted(event) || !el) {
      return;
    }
    const form = deps.forms().find((f) => composedContains(f.container, el));
    if (!form) {
      return;
    }
    touch(interaction, form);
    const control = el.closest("button, input");
    if (control && isSubmitLike(control)) {
      touch(submitIntent, form);
      emitFor(form);
    }
  };

  const onPageHide = (): void => {
    for (const form of known) {
      if (recent(interaction, form, INTERACTION_MS)) {
        emitFor(form);
      }
    }
  };

  doc.addEventListener("input", onInput, true);
  doc.addEventListener("keydown", onKeydown, true);
  doc.addEventListener("click", onClick, true);
  doc.defaultView?.addEventListener("pagehide", onPageHide);

  const refresh = (forms: LoginForm[]): void => {
    for (const form of known) {
      const removed = passwordFields(form).some((el) => model.has(el) && !el.isConnected);
      if (removed && recent(interaction, form, INTERACTION_MS)) {
        emitFor(form);
      }
    }
    for (const el of model.keys()) {
      if (!el.isConnected) {
        model.delete(el);
      }
    }
    known = forms;
    forms.forEach(watch);
  };

  refresh(deps.forms());

  return {
    markFilled(el) {
      model.set(el, null);
    },
    refresh,
    dispose() {
      doc.removeEventListener("input", onInput, true);
      doc.removeEventListener("keydown", onKeydown, true);
      doc.removeEventListener("click", onClick, true);
      doc.defaultView?.removeEventListener("pagehide", onPageHide);
    },
  };
}
