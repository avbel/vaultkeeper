import type { PopupFillReply, PopupRequest, PopupStatus } from "../shared/popup.ts";
import type { RequestMap, RequestType } from "../shared/protocol.ts";
import type { BeginFillResult, SenderLike } from "./router.ts";

export interface PopupDeps {
  runtimeId: string;
  popupUrl: string;
  activeTabId(): Promise<number | undefined>;
  beginFill(tabId: number, choose: boolean): Promise<BeginFillResult>;
  session: {
    readonly status: PopupStatus;
    ensureReady(): Promise<void>;
    request<T extends RequestType>(
      type: T,
      fields: RequestMap[T]["fields"],
    ): Promise<RequestMap[T]["result"]>;
  };
}

export type PopupReply = { status: PopupStatus } | PopupFillReply | { ok: boolean };

export function createPopupHandler(deps: PopupDeps) {
  function fromPopup(sender: SenderLike): boolean {
    return sender.id === deps.runtimeId && !sender.tab && sender.url === deps.popupUrl;
  }

  return async function handle(message: PopupRequest, sender: SenderLike): Promise<PopupReply> {
    if (!fromPopup(sender)) {
      return { ok: false };
    }
    switch (message.kind) {
      case "popup_status": {
        // The reply carries the current snapshot; progress is pushed as it changes.
        deps.session.ensureReady().catch(() => undefined);
        return { status: deps.session.status };
      }
      case "popup_fill": {
        const tabId = await deps.activeTabId();
        if (tabId === undefined) {
          return { ok: false, reason: "unreachable" };
        }
        const result = await deps.beginFill(tabId, message.choose);
        return result.reached
          ? { ok: true, found: result.found }
          : { ok: false, reason: "unreachable" };
      }
      case "popup_unlock": {
        await deps.session.request("unlock", {});
        return { ok: true };
      }
      case "popup_open_app": {
        await deps.session.request("open_app", { view: message.view });
        return { ok: true };
      }
    }
  };
}
