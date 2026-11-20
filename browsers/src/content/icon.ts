import type { Theme } from "../shared/messages.ts";
import { SHIELD_PATH } from "../shared/shield.ts";
import { SHADOW_TOKENS } from "./theme-css.ts";

const SVG_NS = "http://www.w3.org/2000/svg";
const BUTTON_SIZE = 20;
const EDGE_INSET = 4;
const TOAST_MS = 3500;
const MAX_Z_INDEX = "2147483647";
const MENU_GAP = 4;
const FILL_LABEL = "Fill with Vaultkeeper";

const STYLE = `
${SHADOW_TOKENS}
:host { font-family: var(--font); }
button {
  all: unset; box-sizing: border-box; position: fixed; width: ${BUTTON_SIZE}px; height: ${BUTTON_SIZE}px;
  display: none; align-items: center; justify-content: center; cursor: pointer; pointer-events: auto;
  color: var(--accent); background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius-control);
}
button[data-shown] { display: flex; }
button:hover { background: var(--hover); }
button:focus-visible { outline: 2px solid var(--accent); }
.menu {
  position: fixed; pointer-events: auto; padding: 4px; background: var(--surface-popup);
  border: 1px solid var(--border); border-radius: var(--radius-popup); box-shadow: 0 4px 16px var(--shadow);
}
.menu button.choice {
  position: static; display: flex; width: auto; height: auto; padding: var(--gap) var(--padding);
  font-size: var(--font-body); color: var(--text); background: transparent; border: none; white-space: nowrap;
}
.menu button.choice:hover { background: var(--hover); }
.toast {
  position: fixed; right: var(--padding); bottom: var(--padding); max-width: 320px; pointer-events: none;
  padding: var(--gap) var(--padding); font-size: var(--font-body); color: var(--text);
  background: var(--surface-popup); border: 1px solid var(--border); border-radius: var(--radius-popup);
  box-shadow: 0 4px 16px var(--shadow);
}
`;

function shieldSvg(): SVGSVGElement {
  const svg = document.createElementNS(SVG_NS, "svg");
  for (const [name, value] of Object.entries({
    width: "16",
    height: "16",
    viewBox: "0 0 16 16",
    fill: "currentColor",
    "aria-hidden": "true",
  })) {
    svg.setAttribute(name, value);
  }
  const path = document.createElementNS(SVG_NS, "path");
  path.setAttribute("fill-rule", "evenodd");
  path.setAttribute("d", SHIELD_PATH);
  svg.append(path);
  return svg;
}

export interface IconOptions {
  shadowMode?: "open" | "closed";
  isTrusted?: (event: Event) => boolean;
}

export interface Icon {
  host: HTMLElement;
  show: (field: HTMLInputElement, onClick: () => void, label?: string) => void;
  /** A one-item menu under the icon; `onChoose` runs on a trusted click and closes it. */
  menu: (text: string, onChoose: () => void) => void;
  hide: () => void;
  reposition: () => void;
  toast: (text: string) => void;
  setTheme: (theme: Theme) => void;
  target: () => HTMLInputElement | null;
}

export function createIcon(options: IconOptions = {}): Icon {
  const trusted = options.isTrusted ?? ((event: Event) => event.isTrusted);
  const host = document.createElement("div");
  host.style.cssText = `all: initial; position: fixed; inset: 0; z-index: ${MAX_Z_INDEX}; pointer-events: none;`;
  const shadow = host.attachShadow({ mode: options.shadowMode ?? "closed" });
  const style = document.createElement("style");
  style.textContent = STYLE;
  const button = document.createElement("button");
  button.type = "button";
  button.setAttribute("aria-label", FILL_LABEL);
  button.append(shieldSvg());
  const menuEl = document.createElement("div");
  menuEl.className = "menu";
  menuEl.setAttribute("role", "menu");
  menuEl.hidden = true;
  const choice = document.createElement("button");
  choice.type = "button";
  choice.className = "choice";
  choice.setAttribute("role", "menuitem");
  menuEl.append(choice);
  const toastEl = document.createElement("div");
  toastEl.className = "toast";
  toastEl.setAttribute("role", "status");
  toastEl.hidden = true;
  shadow.append(style, button, menuEl, toastEl);

  let field: HTMLInputElement | null = null;
  let onClick: (() => void) | null = null;
  let onChoose: (() => void) | null = null;
  let toastTimer: ReturnType<typeof setTimeout> | undefined;

  // Keeps focus in the page field so the click does not blur it and hide the icon first.
  for (const el of [button, choice]) {
    el.addEventListener("mousedown", (event) => {
      event.preventDefault();
    });
  }
  choice.addEventListener("click", (event) => {
    if (!trusted(event)) {
      return;
    }
    const chosen = onChoose;
    closeMenu();
    chosen?.();
  });
  button.addEventListener("click", (event) => {
    if (!trusted(event)) {
      return;
    }
    onClick?.();
  });

  const closeMenu = (): void => {
    onChoose = null;
    menuEl.hidden = true;
  };

  const placeMenu = (rect: DOMRect): void => {
    menuEl.style.left = `${Math.round(rect.right - BUTTON_SIZE - EDGE_INSET)}px`;
    menuEl.style.top = `${Math.round(rect.bottom + MENU_GAP)}px`;
  };

  const hide = (): void => {
    field = null;
    onClick = null;
    closeMenu();
    button.removeAttribute("data-shown");
  };

  const reposition = (): void => {
    if (!field) {
      return;
    }
    if (!field.isConnected || field.getClientRects().length === 0) {
      hide();
      return;
    }
    const rect = field.getBoundingClientRect();
    button.style.left = `${Math.round(rect.right - BUTTON_SIZE - EDGE_INSET)}px`;
    button.style.top = `${Math.round(rect.top + (rect.height - BUTTON_SIZE) / 2)}px`;
    button.setAttribute("data-shown", "");
    placeMenu(rect);
  };

  return {
    host,
    show(target, handler, label = FILL_LABEL) {
      if (field !== target) {
        closeMenu();
      }
      field = target;
      onClick = handler;
      button.setAttribute("aria-label", label);
      reposition();
    },
    menu(text, handler) {
      if (!field) {
        return;
      }
      choice.textContent = text;
      onChoose = handler;
      menuEl.hidden = false;
      reposition();
    },
    hide,
    reposition,
    target: () => field,
    toast(text) {
      toastEl.textContent = text;
      toastEl.hidden = false;
      clearTimeout(toastTimer);
      toastTimer = setTimeout(() => {
        toastEl.hidden = true;
      }, TOAST_MS);
    },
    setTheme(theme) {
      if (theme === "system") {
        host.removeAttribute("data-theme");
      } else {
        host.setAttribute("data-theme", theme);
      }
    },
  };
}
