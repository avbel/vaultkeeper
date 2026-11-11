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
const USERNAME_STEP_NAME = /user|login|identifier/i;
const EMAIL_NAME = /e-?mail/i;
const USERNAME_WORDS = /e-?mail|user|login|account|identifier|phone|mobile/i;
const NOT_USERNAME_WORDS = /search|captcha|code|otp|one.?time|verif|coupon|promo/i;

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

function labelText(el: HTMLInputElement): string {
  const parts = [el.placeholder, el.title, el.getAttribute("aria-label") ?? ""];
  for (const label of el.labels ?? []) {
    parts.push(label.textContent ?? "");
  }
  const root = el.getRootNode() as Document | ShadowRoot;
  for (const id of (el.getAttribute("aria-labelledby") ?? "").split(/\s+/).filter(Boolean)) {
    parts.push(root.getElementById(id)?.textContent ?? "");
  }
  return parts.join(" ");
}

// Captcha, one-time code and search boxes sit next to identifier fields on Reddit, PayPal and Google.
function isNotUsername(el: HTMLInputElement): boolean {
  const tokens = autocompleteTokens(el);
  if (el.type === "search" || tokens.has("one-time-code")) {
    return true;
  }
  if ([...tokens].some((token) => token.startsWith("cc-"))) {
    return true;
  }
  return NOT_USERNAME_WORDS.test(`${labelText(el)} ${el.name}`);
}

function isUsernameCandidate(el: HTMLInputElement): boolean {
  if (isPasswordField(el) || isNotUsername(el)) {
    return false;
  }
  const tokens = autocompleteTokens(el);
  return USERNAME_TYPES.has(el.type) || tokens.has("username") || tokens.has("email");
}

interface Ctx {
  shown: HTMLInputElement[];
  hiddenPasswords: HTMLInputElement[];
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

const SIGN_IN = /sign.?in|log.?in|log.?on/i;
const SIGN_UP = /sign.?up|regist|create|join|enrol/i;
const SUBMIT = "button:not([type]), button[type=submit], input[type=submit], input[type=image]";

function submitLabels(container: Element): string[] {
  const labels = [
    container.id,
    container.getAttribute("name") ?? "",
    container.getAttribute("action") ?? "",
  ];
  for (const el of container.querySelectorAll(SUBMIT)) {
    labels.push(
      el.id,
      el.getAttribute("name") ?? "",
      el.getAttribute("value") ?? "",
      el.getAttribute("aria-label") ?? "",
      el.textContent ?? "",
    );
  }
  return labels.filter(Boolean);
}

// Some login forms (developer.ebay.com) tag their only password field new-password to keep the
// browser's own manager away; the form's or its submit's sign-in wording overrides the token.
function isSignInForm(container: Element): boolean {
  const labels = submitLabels(container);
  return labels.some((l) => SIGN_IN.test(l)) && !labels.some((l) => SIGN_UP.test(l));
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
  const username = usernameBefore(ctx, group.container, first);
  if (username && !multiple && fresh.length === 1 && isSignInForm(group.container)) {
    current.push(...fresh.splice(0));
  }
  const form: LoginForm = { newPasswords: fresh, container: group.container };
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

type StepSignal = "strong" | "weak";

// webauthn is only ever put on login identifier fields (Amazon's has no other hint). Anything else
// is weak: a newsletter box (xda-developers.com footer: type=email name=email) reads like Temu's
// "Email or phone number" identifier.
function usernameStepSignal(el: HTMLInputElement): StepSignal | undefined {
  if (isPasswordField(el) || isNotUsername(el)) {
    return undefined;
  }
  const tokens = autocompleteTokens(el);
  if (tokens.has("username") || tokens.has("webauthn")) {
    return "strong";
  }
  if (!USERNAME_TYPES.has(el.type)) {
    return undefined;
  }
  if (USERNAME_STEP_NAME.test(el.name) || USERNAME_STEP_NAME.test(el.id)) {
    return "strong";
  }
  const emailish = el.type === "email" || EMAIL_NAME.test(el.name) || EMAIL_NAME.test(el.id);
  return emailish || USERNAME_WORDS.test(labelText(el)) ? "weak" : undefined;
}

// eBay, Google, X and PayPal keep the step-two password in the DOM, hidden, beside the identifier.
function hasLoginContext(ctx: Ctx, container: Element, el: HTMLInputElement): boolean {
  if (ctx.hiddenPasswords.some((p) => composedContains(container, p))) {
    return true;
  }
  const doc = el.ownerDocument;
  return (
    isSignInForm(container) ||
    [doc.location?.pathname ?? "", doc.title].some((t) => SIGN_IN.test(t))
  );
}

function findUsernameSteps(ctx: Ctx, taken: LoginForm[]): LoginForm[] {
  const steps: LoginForm[] = [];
  for (const el of ctx.shown) {
    const signal = usernameStepSignal(el);
    if (!signal) {
      continue;
    }
    if (taken.some((f) => composedContains(f.container, el))) {
      continue;
    }
    const container = stepContainerOf(ctx, el);
    if (signal === "weak" && !hasLoginContext(ctx, container, el)) {
      continue;
    }
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
    hiddenPasswords: all.filter((el) => isPasswordField(el) && !visible(el)),
    order: new Map(all.map((el, index) => [el, index])),
  };
  const passwords = ctx.shown.filter(isPasswordField);
  const withPasswords = groupPasswords(ctx, passwords).map((g) => toLoginForm(ctx, g));
  const steps = findUsernameSteps(ctx, withPasswords);
  return [...withPasswords, ...steps].sort((a, b) => firstField(ctx, a) - firstField(ctx, b));
}
