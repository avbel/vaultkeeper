import { api } from "../shared/api.ts";
import type { PopupPush, PopupRequest, PopupStatus } from "../shared/popup.ts";

const SITE_ORIGINS = ["https://*/*", "http://*/*"];

const UNAVAILABLE: Record<string, { text: string; hint: string }> = {
  not_running: {
    text: "Vaultkeeper is not running.",
    hint: "Start the Vaultkeeper app, then try again.",
  },
  disabled: {
    text: "Browser integration is turned off.",
    hint: "Turn it on in Vaultkeeper under Settings, Browsers.",
  },
  version: {
    text: "Vaultkeeper and this extension do not match.",
    hint: "Update both to the latest version.",
  },
  unverified_parent: {
    text: "Vaultkeeper does not recognise this browser.",
    hint: "Only Google Chrome and Firefox are supported.",
  },
  busy: {
    text: "Vaultkeeper has too many browser connections.",
    hint: "Close other browser windows and try again.",
  },
};

let siteAccess = true;
let status: PopupStatus | null = null;
let busy = false;

const root = document.getElementById("root") as HTMLElement;

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: { class?: string; text?: string } = {},
  children: Node[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (props.class) {
    node.className = props.class;
  }
  if (props.text !== undefined) {
    node.textContent = props.text;
  }
  node.append(...children);
  return node;
}

function icon(name: string): HTMLElement {
  const span = el("span", { class: "icon" });
  span.style.setProperty("--icon", `url("icons/${name}.svg")`);
  span.setAttribute("aria-hidden", "true");
  return span;
}

function message(kind: "" | "warn" | "danger", iconName: string, text: string): HTMLElement {
  return el("p", { class: `message ${kind}`.trim() }, [icon(iconName), el("span", { text })]);
}

function button(label: string, onClick: () => void, primary = false): HTMLButtonElement {
  const node = el("button", { text: label, class: primary ? "primary" : "" });
  node.type = "button";
  node.disabled = busy;
  node.addEventListener("click", onClick);
  return node;
}

async function send(request: PopupRequest): Promise<unknown> {
  return api.runtime.sendMessage(request);
}

async function refresh(): Promise<void> {
  const reply = (await send({ kind: "popup_status" })) as { status?: PopupStatus } | undefined;
  if (reply?.status) {
    status = reply.status;
    render();
  }
}

async function runBusy(request: PopupRequest, closeAfter: boolean): Promise<void> {
  busy = true;
  render();
  try {
    await send(request);
  } finally {
    busy = false;
  }
  if (closeAfter) {
    window.close();
  } else {
    render();
  }
}

function body(current: PopupStatus | null): HTMLElement[] {
  if (!siteAccess) {
    return [
      message(
        "warn",
        "warning",
        "Vaultkeeper cannot see web pages. Allow site access in the browser's extension settings.",
      ),
    ];
  }
  if (!current || current.phase === "idle" || current.phase === "connecting") {
    return [el("p", { class: "hint", text: "Connecting to Vaultkeeper…" })];
  }
  switch (current.phase) {
    case "unavailable": {
      const known = UNAVAILABLE[current.reason ?? ""];
      const text = known?.text ?? "Cannot reach Vaultkeeper.";
      const hint = known?.hint ?? current.reason ?? "";
      return [
        message("danger", "warning", text),
        el("p", { class: "hint", text: hint }),
        button("Try again", () => void refresh()),
      ];
    }
    case "denied":
      return [
        message("danger", "warning", "Vaultkeeper did not approve this browser."),
        button("Try again", () => void refresh()),
      ];
    case "error":
      return [
        message(
          "danger",
          "warning",
          `Vaultkeeper returned an error (${current.reason ?? "unknown"}).`,
        ),
        button("Try again", () => void refresh()),
      ];
    case "pairing":
      return [
        el("p", { text: "Confirm this code in Vaultkeeper:" }),
        el("div", { class: "code", text: current.fingerprint ?? "" }),
      ];
    default:
      return readyBody(current);
  }
}

function readyBody(current: PopupStatus): HTMLElement[] {
  if (current.state === "logged_out") {
    return [
      message("warn", "lock", "Sign in to Vaultkeeper first."),
      el("div", { class: "actions" }, [
        button(
          "Open Vaultkeeper",
          () => void runBusy({ kind: "popup_open_app", view: "manager" }, true),
          true,
        ),
      ]),
    ];
  }
  if (current.state === "locked") {
    return [
      message("", "lock", "Vaultkeeper is locked."),
      el("div", { class: "actions" }, [
        button("Unlock", () => void runBusy({ kind: "popup_unlock" }, true), true),
      ]),
    ];
  }
  return [
    el("div", { class: "actions" }, [
      button(
        "Fill this page",
        () => void runBusy({ kind: "popup_fill", choose: false }, true),
        true,
      ),
      button(
        "Choose another login…",
        () => void runBusy({ kind: "popup_fill", choose: true }, true),
      ),
      button(
        "Open Vaultkeeper",
        () => void runBusy({ kind: "popup_open_app", view: "manager" }, true),
      ),
    ]),
  ];
}

function render(): void {
  const theme = status?.theme ?? "system";
  if (theme === "system") {
    delete document.documentElement.dataset.theme;
  } else {
    document.documentElement.dataset.theme = theme;
  }
  const nodes: Node[] = [
    el("header", {}, [icon("key"), el("span", { text: "Vaultkeeper" })]),
    ...body(status),
  ];
  if (status?.fingerprint) {
    nodes.push(
      el("footer", {}, [
        document.createTextNode("This browser: "),
        el("span", { class: "mono", text: status.fingerprint }),
      ]),
    );
  }
  root.replaceChildren(...nodes);
}

api.runtime.onMessage.addListener((message: unknown, sender) => {
  const push = message as PopupPush | undefined;
  if (sender.id === api.runtime.id && push?.kind === "popup_status_changed") {
    status = push.status;
    render();
  }
  return false;
});

async function start(): Promise<void> {
  render();
  siteAccess = await Promise.resolve(api.permissions.contains({ origins: SITE_ORIGINS })).catch(
    () => true,
  );
  render();
  if (siteAccess) {
    await refresh();
  }
}

void start();
