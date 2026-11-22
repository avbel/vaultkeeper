import type { PopupFillReply, PopupRequest } from "../shared/popup.ts";

export const NOTICE_NO_FORM = "No login form found on this page.";
export const NOTICE_UNREACHABLE = "Vaultkeeper cannot reach this page. Reload it and try again.";
export const NOTICE_NO_RESPONSE = "Vaultkeeper did not respond. Try again.";
// Neutral on purpose: an unlock the user dismissed in the app fails the same way as a lost one.
export const NOTICE_FAILED = "Vaultkeeper could not do that. Try again.";

function fillNotice(reply: PopupFillReply | undefined): string | null {
  if (!reply) {
    return NOTICE_NO_RESPONSE;
  }
  if (!reply.ok) {
    return NOTICE_UNREACHABLE;
  }
  return reply.found ? null : NOTICE_NO_FORM;
}

/** What the popup says after `request` got `reply`; null when it succeeded. */
export function replyNotice(request: PopupRequest, reply: unknown): string | null {
  if (request.kind === "popup_fill") {
    return fillNotice(reply as PopupFillReply | undefined);
  }
  return (reply as { ok?: unknown } | null | undefined)?.ok === false ? NOTICE_FAILED : null;
}
