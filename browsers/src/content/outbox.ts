import type { ToBackground } from "../shared/messages.ts";
import type { Filler } from "./fill.ts";
import type { Generator } from "./generate.ts";
import { TOAST } from "./toast-text.ts";

export interface RefusalDeps {
  filler: Pick<Filler, "cancel">;
  generator: Pick<Generator, "cancel">;
  toast: (text: string) => void;
}

/** Drops the request the background will never answer and tells the user, if they asked for it. */
export function handleRefusal(message: ToBackground, deps: RefusalDeps): void {
  switch (message.kind) {
    case "fill_request":
      if (deps.filler.cancel(message.nonce) && !message.auto) {
        deps.toast(TOAST.generic);
      }
      break;
    case "generate_request":
      if (deps.generator.cancel(message.nonce)) {
        deps.toast(TOAST.generateFailed);
      }
      break;
    default:
      // A save candidate has no outcome to report, and the passkey relay sends its own.
      break;
  }
}

export interface SendDeps {
  forward: (message: ToBackground) => Promise<boolean>;
  refused: (message: ToBackground) => void;
  /** True when the extension behind this script is gone; the script has then shut itself down. */
  orphaned: () => boolean;
}

export function createSend(deps: SendDeps): (message: ToBackground) => void {
  return (message) => {
    void deps.forward(message).then((accepted) => {
      if (!accepted && !deps.orphaned()) {
        deps.refused(message);
      }
    });
  };
}
