import type { Theme } from "../shared/messages.ts";
import { SHADOW_TOKENS } from "./theme-css.ts";

const SVG_NS = "http://www.w3.org/2000/svg";
const BUTTON_SIZE = 20;
const EDGE_INSET = 4;
const TOAST_MS = 3500;
const MAX_Z_INDEX = "2147483647";

const STYLE = `
${SHADOW_TOKENS}
:host { font-family: var(--font); }
button {
  all: unset; box-sizing: border-box; position: fixed; width: ${BUTTON_SIZE}px; height: ${BUTTON_SIZE}px;
  display: none; align-items: center; justify-content: center; cursor: pointer; pointer-events: auto;
  color: var(--text-muted); background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius-control);
}
button[data-shown] { display: flex; }
button:hover { color: var(--accent); background: var(--hover); }
button:focus-visible { outline: 2px solid var(--accent); }
.toast {
  position: fixed; right: var(--padding); bottom: var(--padding); max-width: 320px; pointer-events: none;
  padding: var(--gap) var(--padding); font-size: var(--font-body); color: var(--text);
  background: var(--surface-popup); border: 1px solid var(--border); border-radius: var(--radius-popup);
  box-shadow: 0 4px 16px var(--shadow);
}
`;

function keySvg(): SVGSVGElement {
  const svg = document.createElementNS(SVG_NS, "svg");
  for (const [name, value] of Object.entries({
    width: "14",
    height: "14",
    viewBox: "0 0 16 16",
    fill: "none",
    stroke: "currentColor",
    "stroke-width": "1.5",
    "stroke-linecap": "round",
    "stroke-linejoin": "round",
    "aria-hidden": "true",
  })) {
    svg.setAttribute(name, value);
  }
  const circle = document.createElementNS(SVG_NS, "circle");
  circle.setAttribute("cx", "5");
  circle.setAttribute("cy", "8");
  circle.setAttribute("r", "2.8");
  const path = document.createElementNS(SVG_NS, "path");
  path.setAttribute("d", "M7.8 8H14M12 8v2.5M14 8v2");
  svg.append(circle, path);
  return svg;
}

export interface IconOptions {
  shadowMode?: "open" | "closed";
  isTrusted?: (event: Event) => boolean;
}

export interface Icon {
  host: HTMLElement;
  show: (field: HTMLInputElement, onClick: () => void) => void;
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
  button.setAttribute("aria-label", "Fill with Vaultkeeper");
  button.append(keySvg());
  const toastEl = document.createElement("div");
  toastEl.className = "toast";
  toastEl.setAttribute("role", "status");
  toastEl.hidden = true;
  shadow.append(style, button, toastEl);

  let field: HTMLInputElement | null = null;
  let onClick: (() => void) | null = null;
  let toastTimer: ReturnType<typeof setTimeout> | undefined;

  // Keeps focus in the page field so the click does not blur it and hide the icon first.
  button.addEventListener("mousedown", (event) => {
    event.preventDefault();
  });
  button.addEventListener("click", (event) => {
    if (!trusted(event)) {
      return;
    }
    onClick?.();
  });

  const hide = (): void => {
    field = null;
    onClick = null;
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
  };

  return {
    host,
    show(target, handler) {
      field = target;
      onClick = handler;
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
