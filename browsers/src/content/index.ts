import { api } from "../shared/api.ts";
import type { Theme, ToBackground, ToContent } from "../shared/messages.ts";
import { forwardToBackground } from "../shared/send.ts";
import { createAutofill } from "./autofill.ts";
import { beginFill } from "./begin.ts";
import { createCapture } from "./capture.ts";
import { findLoginForms, type LoginForm } from "./detect.ts";
import { composedContains } from "./dom.ts";
import { createFiller } from "./fill.ts";
import { createGenerator } from "./generate.ts";
import { createIcon } from "./icon.ts";
import { createSend, handleRefusal } from "./outbox.ts";
import { affectsForms, createRescanScheduler } from "./rescan.ts";
import { MENU, TOAST, toastForError, toastForGenerateError } from "./toast-text.ts";

const GUARD = "__vaultkeeperContentLoaded";
const THEMES: readonly string[] = ["light", "dark", "system"];

const guarded = globalThis as unknown as Record<string, boolean | undefined>;

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

// An extension update or reload leaves this script running against a runtime that is gone.
function runtimeGone(): boolean {
  try {
    return !api.runtime.id;
  } catch {
    return true;
  }
}

function main(): void {
  let forms: LoginForm[] = [];
  const icon = createIcon();

  const send = createSend({
    forward: (message) =>
      forwardToBackground((m: ToBackground) => api.runtime.sendMessage(m), message),
    refused: (message) => {
      handleRefusal(message, { filler, generator, toast: icon.toast });
    },
    orphaned: () => shutDownIfOrphaned(),
  });

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

  const autofill = createAutofill({ filler });

  const generator = createGenerator({
    send,
    onGenerated: (form, fields, value) => {
      capture.markGenerated(form, fields, value);
    },
  });

  const offerGenerated = (form: LoginForm, anchor: HTMLInputElement): void => {
    icon.menu(MENU.generate, () => {
      if (generator.request(form, anchor) === "too_short") {
        icon.toast(TOAST.fieldTooShort);
      }
    });
  };

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

  const onFocusIn = (event: Event): void => {
    const el = event.composedPath()[0];
    if (!(el instanceof HTMLInputElement) || shutDownIfOrphaned()) {
      return;
    }
    const form = formOf(el);
    if (form && (form.username === el || form.password === el)) {
      icon.show(el, () => {
        filler.request(form, false);
      });
    } else if (form?.newPasswords.includes(el)) {
      icon.show(
        el,
        () => {
          offerGenerated(form, el);
        },
        MENU.generateLabel,
      );
    } else {
      icon.hide();
    }
  };

  const onFocusOut = (): void => {
    icon.hide();
  };

  const onVisibilityChange = (): void => {
    autofill.attempt(rescan());
  };

  const onMessage = (
    message: unknown,
    sender: chrome.runtime.MessageSender,
    sendResponse: (response: { found: boolean }) => void,
  ): void => {
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
        if (outcome.claimed && outcome.filled === 0 && !outcome.auto) {
          icon.toast(TOAST.generic);
        }
        break;
      }
      case "fill_error":
        applyTheme(message.theme);
        // `no_auto` is the answer to a fill the user never asked for: nothing to report.
        if (filler.applyError(message) && message.code !== "no_auto") {
          icon.toast(toastForError(message.code));
        }
        break;
      case "generate_result": {
        applyTheme(message.theme);
        const outcome = generator.applyResult(message);
        if (outcome !== "ignored") {
          const filled = message.saves ? TOAST.generated : TOAST.generatedPrivate;
          icon.toast(outcome === "filled" ? filled : TOAST.generatedChanged);
        }
        break;
      }
      case "generate_error":
        applyTheme(message.theme);
        if (generator.applyError(message)) {
          icon.toast(toastForGenerateError(message.code));
        }
        break;
      case "passkey_result":
        // The passkey relay answers these.
        break;
    }
  };

  // Any change can move the field the icon sits on; only some can change the forms.
  const scheduler = createRescanScheduler((relevant) => {
    if (relevant) {
      autofill.attempt(rescan());
    }
    icon.reposition();
  });

  const observer = new MutationObserver((records) => {
    if (!shutDownIfOrphaned()) {
      scheduler.schedule(affectsForms(records));
    }
  });

  function shutDownIfOrphaned(): boolean {
    if (!runtimeGone()) {
      return false;
    }
    observer.disconnect();
    scheduler.cancel();
    capture.dispose();
    document.removeEventListener("focusin", onFocusIn, true);
    document.removeEventListener("focusout", onFocusOut, true);
    document.removeEventListener("visibilitychange", onVisibilityChange);
    window.removeEventListener("resize", icon.reposition);
    window.removeEventListener("scroll", icon.reposition, true);
    try {
      api.runtime.onMessage.removeListener(onMessage);
    } catch {
      // A dead runtime may refuse; its listeners are never called again either way.
    }
    icon.host.remove();
    delete guarded[GUARD];
    return true;
  }

  document.addEventListener("focusin", onFocusIn, true);
  document.addEventListener("focusout", onFocusOut, true);
  document.addEventListener("visibilitychange", onVisibilityChange);
  window.addEventListener("resize", icon.reposition);
  window.addEventListener("scroll", icon.reposition, true);
  api.runtime.onMessage.addListener(onMessage);
  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ["style", "class", "hidden", "disabled", "readonly", "type"],
  });

  autofill.attempt(rescan());
  document.documentElement.append(icon.host);
}

// A page open before the extension loaded gets the script injected on demand; running it twice
// in the same isolated world would register every listener and a second icon again. A script
// that shut itself down after an update clears the flag, so a later injection runs again.
if (!guarded[GUARD]) {
  guarded[GUARD] = true;
  main();
}
