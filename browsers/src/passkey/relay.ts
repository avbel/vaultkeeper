// The isolated-world half of the passkey bridge: forwards the page script's requests to the
// background, which decides the origin from the sender, and answers on each request's port.

import { api } from "../shared/api.ts";
import type { ToBackground } from "../shared/messages.ts";
import { CANCEL, type Outcome, parseOutcome, parseRequest } from "./bridge.ts";

function forward(message: ToBackground): Promise<boolean> {
  return Promise.resolve(api.runtime.sendMessage(message)).then(
    (answer: { accepted?: boolean } | undefined) => answer?.accepted === true,
    () => false,
  );
}

function main(): void {
  /** Ports of the requests still waiting for the background, by nonce. */
  const waiting = new Map<string, MessagePort>();

  const answer = (nonce: string, outcome: Outcome): void => {
    const port = waiting.get(nonce);
    if (port) {
      waiting.delete(nonce);
      port.postMessage(outcome);
      port.close();
    }
  };

  window.addEventListener("message", (event: MessageEvent) => {
    if (event.source !== window || event.origin !== window.location.origin) {
      return;
    }
    const request = parseRequest(event.data);
    const port = event.ports[0];
    if (!request || !port || waiting.has(request.id)) {
      return;
    }
    const nonce = request.id;
    waiting.set(nonce, port);
    port.onmessage = (message: MessageEvent) => {
      if (message.data === CANCEL && waiting.delete(nonce)) {
        port.close();
        void forward({ kind: "passkey_cancel", nonce });
      }
    };
    void forward({
      kind: "passkey_request",
      nonce,
      ceremony: request.ceremony,
      options: request.options,
    }).then((accepted) => {
      if (!accepted) {
        answer(nonce, { outcome: "fallback" });
      }
    });
  });

  api.runtime.onMessage.addListener((message: unknown, sender: chrome.runtime.MessageSender) => {
    if (sender.id !== api.runtime.id || typeof message !== "object" || message === null) {
      return;
    }
    const m = message as { kind?: unknown; nonce?: unknown };
    const outcome = parseOutcome(message);
    if (m.kind === "passkey_result" && typeof m.nonce === "string" && outcome) {
      answer(m.nonce, outcome);
    }
  });
}

const GUARD = "__vaultkeeperPasskeyRelay";
const guarded = globalThis as unknown as Record<string, boolean | undefined>;
if (!guarded[GUARD]) {
  guarded[GUARD] = true;
  main();
}
