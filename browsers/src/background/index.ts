import { api } from "../shared/api.ts";
import {
  POPUP_KINDS,
  type PopupPush,
  type PopupRequest,
  type PopupStatus,
} from "../shared/popup.ts";
import type { Theme } from "../shared/protocol.ts";
import { NativeClient } from "./native.ts";
import { callerString, getOrCreateKeyPair } from "./pairing.ts";
import { createPopupHandler } from "./popup-handler.ts";
import { createRouter, type SenderLike } from "./router.ts";
import { Session } from "./session.ts";

const MENU_FILL = "vaultkeeper-fill";
const MENU_CHOOSE = "vaultkeeper-choose";

let lastTheme: Theme | null = null;

const native = new NativeClient({
  connectNative: (name) => api.runtime.connectNative(name) as never,
  lastError: () => api.runtime.lastError?.message,
});

const session = new Session({
  native,
  keys: () => getOrCreateKeyPair(),
  caller: callerString(api.runtime),
  extensionVersion: api.runtime.getManifest().version,
  onChange: (status) => {
    pushStatus(status);
    if (status.theme !== lastTheme) {
      lastTheme = status.theme;
      void broadcastTheme(status.theme);
    }
  },
});

function pushStatus(status: PopupStatus): void {
  const push: PopupPush = { kind: "popup_status_changed", status };
  // Rejects when no popup is open.
  Promise.resolve(api.runtime.sendMessage(push)).catch(() => undefined);
}

async function broadcastTheme(theme: Theme): Promise<void> {
  const tabs = await api.tabs.query({ url: ["https://*/*", "http://*/*"] });
  for (const tab of tabs) {
    if (tab.id !== undefined) {
      Promise.resolve(api.tabs.sendMessage(tab.id, { kind: "theme", theme })).catch(
        () => undefined,
      );
    }
  }
}

const router = createRouter({
  runtimeId: api.runtime.id,
  getTab: (tabId) => api.tabs.get(tabId),
  sendToTab: (tabId, message, frameId) => api.tabs.sendMessage(tabId, message, { frameId }),
  session,
});

const popup = createPopupHandler({
  runtimeId: api.runtime.id,
  popupUrl: api.runtime.getURL("popup.html"),
  activeTabId: async () => {
    const [tab] = await api.tabs.query({ active: true, currentWindow: true });
    return tab?.id;
  },
  beginFill: (tabId, choose) => router.beginFill(tabId, choose),
  session,
});

function isPopupRequest(message: unknown): message is PopupRequest {
  return (
    typeof message === "object" &&
    message !== null &&
    POPUP_KINDS.includes((message as { kind?: unknown }).kind as string)
  );
}

api.runtime.onMessage.addListener((message: unknown, sender, sendResponse) => {
  const reply = isPopupRequest(message)
    ? popup(message, sender as SenderLike)
    : router.handleContentMessage(message, sender as SenderLike);
  reply.then(sendResponse, () => {
    sendResponse({ ok: false });
  });
  return true;
});

async function fillActiveTab(tabId: number | undefined, choose: boolean): Promise<void> {
  if (tabId === undefined) {
    return;
  }
  await router.beginFill(tabId, choose).catch(() => undefined);
}

api.commands.onCommand.addListener((command, tab) => {
  if (command === "fill") {
    void fillActiveTab(tab?.id, false);
  }
});

api.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === MENU_FILL) {
    void fillActiveTab(tab?.id, false);
  } else if (info.menuItemId === MENU_CHOOSE) {
    void fillActiveTab(tab?.id, true);
  }
});

api.runtime.onInstalled.addListener(() => {
  api.contextMenus.removeAll(() => {
    api.contextMenus.create({
      id: MENU_FILL,
      title: "Fill with Vaultkeeper",
      contexts: ["editable"],
    });
    api.contextMenus.create({
      id: MENU_CHOOSE,
      title: "Choose another login…",
      contexts: ["editable"],
    });
  });
});
