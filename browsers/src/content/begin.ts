import type { LoginForm } from "./detect.ts";
import { composedContains } from "./dom.ts";
import type { Filler } from "./fill.ts";
import { TOAST } from "./toast-text.ts";

export interface BeginDeps {
  rescan: () => LoginForm[];
  active: () => Element | null;
  filler: Pick<Filler, "request" | "isPending">;
  toast: (text: string) => void;
}

// Returns whether a fill is under way: a request was started or one is already in flight.
export function beginFill(deps: BeginDeps, choose: boolean): boolean {
  const forms = deps.rescan();
  const active = deps.active();
  const target =
    (active && forms.find((f) => composedContains(f.container, active))) ||
    forms.find((f) => f.password) ||
    forms[0];
  if (!target) {
    deps.toast(TOAST.noForm);
    return false;
  }
  if (deps.filler.isPending()) {
    return true;
  }
  const started = deps.filler.request(target, choose);
  if (!started) {
    deps.toast(TOAST.noForm);
  }
  return started;
}
