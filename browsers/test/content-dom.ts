import { findLoginForms, type LoginForm } from "../src/content/detect.ts";

const hiddenByStyle = (el: Element): boolean => {
  for (
    let node: Element | null = el;
    node;
    node = node.parentElement ?? (node.getRootNode() as ShadowRoot).host ?? null
  ) {
    if (node.hasAttribute("hidden") || /display:\s*none/.test(node.getAttribute("style") ?? "")) {
      return true;
    }
  }
  return false;
};

export const visible = (el: HTMLInputElement): boolean =>
  el.isConnected && !el.disabled && !el.readOnly && !hiddenByStyle(el);

export function render(html: string): HTMLElement {
  document.body.innerHTML = html;
  return document.body;
}

export function detect(): LoginForm[] {
  return findLoginForms(document, { isVisible: visible });
}

export function input(selector: string, root: ParentNode = document): HTMLInputElement {
  const el = root.querySelector(selector);
  if (!el) {
    throw new Error(`missing ${selector}`);
  }
  return el as HTMLInputElement;
}

function fire(el: HTMLInputElement, inputType: string, data: string | null): void {
  el.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, inputType, data }));
}

export function keystroke(el: HTMLInputElement, char: string): void {
  el.dispatchEvent(new Event("beforeinput", { bubbles: true, composed: true, cancelable: true }));
  el.value += char;
  fire(el, "insertText", char);
}

// Replaces the field content the way a user would: empty it, then type character by character.
export function type(el: HTMLInputElement, text: string): void {
  if (el.value !== "") {
    el.value = "";
    fire(el, "deleteContentBackward", null);
  }
  for (const char of text) {
    keystroke(el, char);
  }
}

export function pressEnter(el: Element): void {
  el.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true, composed: true }));
}
