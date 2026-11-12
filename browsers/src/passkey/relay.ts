// The isolated-world half of the passkey bridge: forwards the page script's requests to the
// background, which decides the origin from the sender, and posts the answers back.

import { api } from "../shared/api.ts";
import type { ToBackground } from "../shared/messages.ts";
import { CHANNEL, type Outcome, parseFromPage, type ToPage } from "./bridge.ts";

function reply(id: string, outcome: Outcome): void {
  const message: ToPage = { channel: CHANNEL, direction: "reply", id, ...outcome };
  window.postMessage(message, window.location.origin);
}

function forward(message: ToBackground): Promise<boolean> {
  return Promise.resolve(api.runtime.sendMessage(message)).then(
    (answer: { accepted?: boolean } | undefined) => answer?.accepted === true,
    () => false,
  );
}

function main(): void {
  window.addEventListener("message", (event: MessageEvent) => {
    if (event.source !== window) {
      return;
    }
    const message = parseFromPage(event.data);
    if (!message) {
      return;
    }
    if (message.direction === "cancel") {
      void forward({ kind: "passkey_cancel", nonce: message.id });
      return;
    }
    void forward({
      kind: "passkey_request",
      nonce: message.id,
      ceremony: message.ceremony,
      options: message.options,
    }).then((accepted) => {
      if (!accepted) {
        reply(message.id, { outcome: "fallback" });
      }
    });
  });

  api.runtime.onMessage.addListener((message: unknown, sender: chrome.runtime.MessageSender) => {
    if (sender.id !== api.runtime.id || typeof message !== "object" || message === null) {
      return;
    }
    const m = message as { kind?: unknown; nonce?: unknown; outcome?: Outcome };
    if (m.kind === "passkey_result" && typeof m.nonce === "string" && m.outcome) {
      reply(m.nonce, m.outcome);
    }
  });
}

const GUARD = "__vaultkeeperPasskeyRelay";
const guarded = globalThis as unknown as Record<string, boolean | undefined>;
if (!guarded[GUARD]) {
  guarded[GUARD] = true;
  main();
}
