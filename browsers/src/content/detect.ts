import { composedClosest, composedContains, composedParent } from "./dom.ts";

export interface LoginForm {
  username?: HTMLInputElement;
  password?: HTMLInputElement;
  newPasswords: HTMLInputElement[];
  container: Element;
}

export interface DetectOptions {
  isVisible?: (el: HTMLInputElement) => boolean;
}

const MIN_SIZE_PX = 8;
const MIN_OPACITY = 0.1;
const USERNAME_TYPES = new Set(["text", "email", "tel"]);
const USERNAME_STEP_NAME = /user|login|email|identifier/i;

export function isVisible(el: HTMLInputElement): boolean {
  if (!el.isConnected || el.disabled || el.readOnly) {
    return false;
  }
  if (el.getClientRects().length === 0) {
    return false;
  }
  const rect = el.getBoundingClientRect();
  if (rect.width < MIN_SIZE_PX || rect.height < MIN_SIZE_PX) {
    return false;
  }
  const style = el.ownerDocument.defaultView?.getComputedStyle(el);
  if (!style) {
    return false;
  }
  if (style.visibility === "hidden" || style.visibility === "collapse") {
    return false;
  }
  const opacity = Number.parseFloat(style.opacity);
  return Number.isNaN(opacity) || opacity >= MIN_OPACITY;
}

export function autocompleteTokens(el: HTMLInputElement): Set<string> {
  const raw = el.getAttribute("autocomplete") ?? "";
  return new Set(raw.toLowerCase().split(/\s+/).filter(Boolean));
}

export function isPasswordField(el: HTMLInputElement): boolean {
  return el.type === "password";
}

function collectInputs(root: ParentNode, out: HTMLInputElement[]): void {
  for (const el of root.querySelectorAll("*")) {
    if (el.localName === "input") {
      out.push(el as HTMLInputElement);
    }
    if (el.shadowRoot) {
      collectInputs(el.shadowRoot, out);
    }
  }
}

function isUsernameCandidate(el: HTMLInputElement): boolean {
  if (isPasswordField(el)) {
    return false;
  }
  const tokens = autocompleteTokens(el);
  return USERNAME_TYPES.has(el.type) || tokens.has("username") || tokens.has("email");
}

interface Ctx {
  shown: HTMLInputElement[];
  order: Map<Element, number>;
}

function position(ctx: Ctx, el: Element): number {
  return ctx.order.get(el) ?? Number.POSITIVE_INFINITY;
}

function usernameBefore(
  ctx: Ctx,
  container: Element,
  password: HTMLInputElement,
): HTMLInputElement | undefined {
  const limit = position(ctx, password);
  let found: HTMLInputElement | undefined;
  for (const el of ctx.shown) {
    if (position(ctx, el) >= limit) {
      break;
    }
    if (isUsernameCandidate(el) && composedContains(container, el)) {
      found = el;
    }
  }
  return found;
}

function containerOf(ctx: Ctx, password: HTMLInputElement): Element {
  const form = composedClosest(password, "form");
  if (form) {
    return form;
  }
  let current = composedParent(password);
  while (current && current.localName !== "body" && current.localName !== "html") {
    if (usernameBefore(ctx, current, password)) {
      return current;
    }
    current = composedParent(current);
  }
  return composedParent(password) ?? password;
}

interface Group {
  container: Element;
  passwords: HTMLInputElement[];
}

function groupPasswords(ctx: Ctx, passwords: HTMLInputElement[]): Group[] {
  const groups: Group[] = [];
  for (const password of passwords) {
    const container = containerOf(ctx, password);
    const hit = groups.find(
      (g) => composedContains(g.container, container) || composedContains(container, g.container),
    );
    if (!hit) {
      groups.push({ container, passwords: [password] });
      continue;
    }
    if (composedContains(container, hit.container)) {
      hit.container = container;
    }
    hit.passwords.push(password);
  }
  return groups;
}

// Several password fields mean a signup or change form, but a lone first field in a
// three-field form is the current password the user is changing.
function toLoginForm(ctx: Ctx, group: Group): LoginForm {
  const passwords = [...group.passwords].sort((a, b) => position(ctx, a) - position(ctx, b));
  const first = passwords[0] as HTMLInputElement;
  const multiple = passwords.length >= 2;
  const current: HTMLInputElement[] = [];
  const fresh: HTMLInputElement[] = [];
  passwords.forEach((el, index) => {
    const tokens = autocompleteTokens(el);
    const isNew =
      tokens.has("new-password") ||
      (multiple && !tokens.has("current-password") && !(passwords.length >= 3 && index === 0));
    (isNew ? fresh : current).push(el);
  });
  const form: LoginForm = { newPasswords: fresh, container: group.container };
  const username = usernameBefore(ctx, group.container, first);
  if (username) {
    form.username = username;
  }
  if (current[0]) {
    form.password = current[0];
  }
  return form;
}

const MAX_TEXT_INPUTS_IN_STEP = 3;
const STEP_ACTION =
  "button, [role=button], input[type=submit], input[type=button], input[type=image]";
const TEXT_LIKE_TYPES = new Set([...USERNAME_TYPES, "search", "url"]);

function textInputCount(ctx: Ctx, container: Element): number {
  return ctx.shown.filter((el) => TEXT_LIKE_TYPES.has(el.type) && composedContains(container, el))
    .length;
}

// Google-style steps have no <form>: the field and its "Next" control share a plain container.
// Climbing stops before a container that holds several text inputs, which is a whole page section.
function stepContainerOf(ctx: Ctx, el: HTMLInputElement): Element {
  const form = composedClosest(el, "form");
  if (form) {
    return form;
  }
  let current = composedParent(el);
  while (current && current.localName !== "body" && current.localName !== "html") {
    if (textInputCount(ctx, current) > MAX_TEXT_INPUTS_IN_STEP) {
      break;
    }
    if (current.querySelector(STEP_ACTION)) {
      return current;
    }
    current = composedParent(current);
  }
  return composedParent(el) ?? el;
}

function looksLikeUsernameStep(el: HTMLInputElement): boolean {
  const tokens = autocompleteTokens(el);
  if (tokens.has("username") || el.type === "email") {
    return true;
  }
  if (!USERNAME_TYPES.has(el.type)) {
    return false;
  }
  return USERNAME_STEP_NAME.test(el.name) || USERNAME_STEP_NAME.test(el.id);
}

function findUsernameSteps(ctx: Ctx, taken: LoginForm[]): LoginForm[] {
  const steps: LoginForm[] = [];
  for (const el of ctx.shown) {
    if (isPasswordField(el) || !looksLikeUsernameStep(el)) {
      continue;
    }
    if (taken.some((f) => composedContains(f.container, el))) {
      continue;
    }
    const container = stepContainerOf(ctx, el);
    const overlaps = [...taken, ...steps].some(
      (f) => composedContains(f.container, container) || composedContains(container, f.container),
    );
    if (!overlaps) {
      steps.push({ username: el, newPasswords: [], container });
    }
  }
  return steps;
}

function firstField(ctx: Ctx, form: LoginForm): number {
  const fields = [form.username, form.password, ...form.newPasswords].filter(
    (el): el is HTMLInputElement => el !== undefined,
  );
  return Math.min(...fields.map((el) => position(ctx, el)));
}

export function findLoginForms(root: ParentNode, options: DetectOptions = {}): LoginForm[] {
  const visible = options.isVisible ?? isVisible;
  const all: HTMLInputElement[] = [];
  collectInputs(root, all);
  const ctx: Ctx = {
    shown: all.filter(visible),
    order: new Map(all.map((el, index) => [el, index])),
  };
  const passwords = ctx.shown.filter(isPasswordField);
  const withPasswords = groupPasswords(ctx, passwords).map((g) => toLoginForm(ctx, g));
  const steps = findUsernameSteps(ctx, withPasswords);
  return [...withPasswords, ...steps].sort((a, b) => firstField(ctx, a) - firstField(ctx, b));
}
