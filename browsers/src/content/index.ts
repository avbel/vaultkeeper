import { api } from "../shared/api.ts";
import type { Theme, ToBackground, ToContent } from "../shared/messages.ts";
import { beginFill } from "./begin.ts";
import { createCapture } from "./capture.ts";
import { findLoginForms, type LoginForm } from "./detect.ts";
import { composedContains } from "./dom.ts";
import { createFiller } from "./fill.ts";
import { createIcon } from "./icon.ts";
import { TOAST, toastForError } from "./toast-text.ts";

const RESCAN_DEBOUNCE_MS = 200;
const THEMES: readonly string[] = ["light", "dark", "system"];

function deepActiveElement(): Element | null {
  let active = document.activeElement;
  while (active?.shadowRoot?.activeElement) {
    active = active.shadowRoot.activeElement;
  }
  return active;
}

function isToContent(value: unknown): value is ToContent {
  return (
    typeof value === "object" && value !== null && typeof (value as ToContent).kind === "string"
  );
}

function main(): void {
  let forms: LoginForm[] = [];
  const icon = createIcon();

  const send = (message: ToBackground): void => {
    Promise.resolve(api.runtime.sendMessage(message)).catch(() => {
      filler.cancel();
      icon.toast(TOAST.generic);
    });
  };

  const filler = createFiller({
    send,
    onFilled: (el) => {
      capture.markFilled(el);
    },
  });

  const capture = createCapture({
    forms: () => forms,
    rescan: () => rescan(),
    emit: (candidate) => {
      send({ kind: "save_candidate", ...candidate });
    },
  });

  function rescan(): LoginForm[] {
    forms = findLoginForms(document);
    capture.refresh(forms);
    return forms;
  }

  const formOf = (el: Element): LoginForm | undefined => {
    const find = () =>
      forms.find(
        (f) => f.username === el || f.password === el || composedContains(f.container, el),
      );
    return find() ?? (rescan(), find());
  };

  const applyTheme = (theme: Theme): void => {
    if (THEMES.includes(theme)) {
      icon.setTheme(theme);
    }
  };

  document.addEventListener(
    "focusin",
    (event) => {
      const el = event.composedPath()[0];
      if (!(el instanceof HTMLInputElement)) {
        return;
      }
      const form = formOf(el);
      if (form && (form.username === el || form.password === el)) {
        icon.show(el, () => {
          filler.request(form, false);
        });
      } else {
        icon.hide();
      }
    },
    true,
  );
  document.addEventListener(
    "focusout",
    () => {
      icon.hide();
    },
    true,
  );
  window.addEventListener("resize", icon.reposition);
  window.addEventListener("scroll", icon.reposition, true);

  api.runtime.onMessage.addListener(
    (
      message: unknown,
      sender: chrome.runtime.MessageSender,
      sendResponse: (response: { found: boolean }) => void,
    ) => {
      if (sender.id !== api.runtime.id || !isToContent(message)) {
        return;
      }
      switch (message.kind) {
        case "begin_fill":
          sendResponse({
            found: beginFill(
              { rescan, active: deepActiveElement, filler, toast: icon.toast },
              message.choose === true,
            ),
          });
          break;
        case "theme":
          applyTheme(message.theme);
          break;
        case "fill_result": {
          applyTheme(message.theme);
          const outcome = filler.applyResult(message);
          if (outcome.claimed && outcome.filled === 0) {
            icon.toast(TOAST.generic);
          }
          break;
        }
        case "fill_error":
          applyTheme(message.theme);
          if (filler.applyError(message)) {
            icon.toast(toastForError(message.code));
          }
          break;
        case "passkey_result":
          // The passkey relay answers these.
          break;
      }
    },
  );

  let timer: ReturnType<typeof setTimeout> | undefined;
  new MutationObserver(() => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      rescan();
      icon.reposition();
    }, RESCAN_DEBOUNCE_MS);
  }).observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ["style", "class", "hidden", "disabled", "readonly", "type"],
  });

  rescan();
  document.documentElement.append(icon.host);
}

// A page open before the extension loaded gets the script injected on demand; running it twice
// in the same isolated world would register every listener and a second icon again.
const GUARD = "__vaultkeeperContentLoaded";
const guarded = globalThis as unknown as Record<string, boolean | undefined>;
if (!guarded[GUARD]) {
  guarded[GUARD] = true;
  main();
}
