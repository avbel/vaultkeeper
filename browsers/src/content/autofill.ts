import type { LoginForm } from "./detect.ts";
import type { Filler } from "./fill.ts";

export interface AutofillDeps {
  filler: Pick<Filler, "request">;
  isTopFrame?: () => boolean;
  protocol?: () => string;
  /** False for a page loaded in a background tab: nothing is filled until the user sees it. */
  isShown?: () => boolean;
}

export interface Autofill {
  /** Asks for a fill of the first sign-in form that qualifies; true only when a request left. */
  attempt: (forms: readonly LoginForm[]) => boolean;
}

// Page scripts can read a filled password, so only the top frame of an encrypted page is ever
// filled without a click, and only once per page load: a later form on the same page waits for
// the user.
export function createAutofill(deps: AutofillDeps): Autofill {
  const isTopFrame = deps.isTopFrame ?? (() => window === window.top);
  const protocol = deps.protocol ?? (() => location.protocol);
  const isShown = deps.isShown ?? (() => document.visibilityState === "visible");
  let asked = false;

  return {
    attempt(forms) {
      if (asked || !isTopFrame() || protocol() !== "https:" || !isShown()) {
        return false;
      }
      for (const form of forms) {
        if (form.password && deps.filler.request(form, false, true)) {
          asked = true;
          return true;
        }
      }
      return false;
    },
  };
}
