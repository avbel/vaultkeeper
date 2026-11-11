import type { FillFields, ToBackground, ToContent } from "../shared/messages.ts";
import { webOrigin, webPath } from "../shared/origin.ts";
import type { RequestMap, RequestType, Theme } from "../shared/protocol.ts";
import { NativeError } from "./native.ts";

export interface SenderLike {
  id?: string | undefined;
  url?: string | undefined;
  frameId?: number | undefined;
  tab?:
    | { id?: number | undefined; url?: string | undefined; incognito?: boolean | undefined }
    | undefined;
}

export interface RouterDeps {
  runtimeId: string;
  getTab(tabId: number): Promise<{ url?: string | undefined }>;
  sendToTab(tabId: number, message: ToContent, frameId: number): Promise<unknown>;
  session: {
    request<T extends RequestType>(
      type: T,
      fields: RequestMap[T]["fields"],
    ): Promise<RequestMap[T]["result"]>;
    readonly theme: Theme;
    readonly status: { phase: string };
  };
}

interface VerifiedSender {
  tabId: number;
  frameId: number;
  origin: string;
  path: string;
  incognito: boolean;
}

const MAX_NONCE = 128;

export function createRouter(deps: RouterDeps) {
  const inFlight = new Set<Promise<void>>();

  function verify(sender: SenderLike): VerifiedSender | null {
    if (sender.id !== deps.runtimeId || !sender.tab || sender.tab.id === undefined) {
      return null;
    }
    const frameOrigin = webOrigin(sender.url);
    const tabOrigin = webOrigin(sender.tab.url);
    if (frameOrigin === null || frameOrigin !== tabOrigin || !sender.url) {
      return null;
    }
    return {
      tabId: sender.tab.id,
      frameId: sender.frameId ?? 0,
      origin: frameOrigin,
      path: webPath(sender.url),
      incognito: sender.tab.incognito === true,
    };
  }

  async function runFill(
    from: VerifiedSender,
    message: Extract<ToBackground, { kind: "fill_request" }>,
  ): Promise<void> {
    const reply = await fillReply(from, message);
    if (reply) {
      await deps.sendToTab(from.tabId, reply, from.frameId).catch(() => undefined);
    }
  }

  async function fillReply(
    from: VerifiedSender,
    message: Extract<ToBackground, { kind: "fill_request" }>,
  ): Promise<ToContent | null> {
    const { nonce } = message;
    try {
      const result = await deps.session.request("fill", {
        origin: from.origin,
        path: from.path,
        choose: message.choose,
        fields: message.fields,
      });
      const tab = await deps.getTab(from.tabId);
      if (webOrigin(tab.url) !== from.origin) {
        return null;
      }
      return {
        kind: "fill_result",
        nonce,
        username: result.username,
        password: result.password,
        theme: deps.session.theme,
      };
    } catch (error) {
      const code = error instanceof NativeError ? error.code : "internal";
      return { kind: "fill_error", nonce, code, theme: deps.session.theme };
    }
  }

  async function runSave(
    from: VerifiedSender,
    message: Extract<ToBackground, { kind: "save_candidate" }>,
  ): Promise<void> {
    // A refused pairing must not re-prompt on every form submit.
    if (from.incognito || deps.session.status.phase === "denied") {
      return;
    }
    try {
      await deps.session.request("save_candidate", {
        origin: from.origin,
        path: from.path,
        username: message.username,
        password: message.password,
        kind: message.candidate,
      });
    } catch {
      // D8: the extension gets no outcome for a save candidate.
    }
  }

  function track(work: Promise<void>): void {
    inFlight.add(work);
    void work.finally(() => {
      inFlight.delete(work);
    });
  }

  return {
    /** Resolves as soon as the message is accepted; the flow continues in the background. */
    async handleContentMessage(
      message: unknown,
      sender: SenderLike,
    ): Promise<{ accepted: boolean }> {
      const from = verify(sender);
      const parsed = parseToBackground(message);
      if (!from || !parsed) {
        return { accepted: false };
      }
      if (parsed.kind === "fill_request") {
        track(runFill(from, parsed));
      } else {
        track(runSave(from, parsed));
      }
      return { accepted: true };
    },

    beginFill(tabId: number, choose: boolean): Promise<unknown> {
      return deps.sendToTab(tabId, { kind: "begin_fill", choose }, 0);
    },

    async idle(): Promise<void> {
      await Promise.all(inFlight);
    },
  };
}

function isFillFields(value: unknown): value is FillFields {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const fields = value as Record<string, unknown>;
  return typeof fields.username === "boolean" && typeof fields.password === "boolean";
}

// Fields such as `origin` or `path` in the body are never read: the sender decides them.
export function parseToBackground(message: unknown): ToBackground | null {
  if (typeof message !== "object" || message === null) {
    return null;
  }
  const m = message as Record<string, unknown>;
  if (m.kind === "fill_request") {
    if (
      typeof m.nonce !== "string" ||
      m.nonce.length === 0 ||
      m.nonce.length > MAX_NONCE ||
      typeof m.choose !== "boolean" ||
      !isFillFields(m.fields)
    ) {
      return null;
    }
    return {
      kind: "fill_request",
      nonce: m.nonce,
      choose: m.choose,
      fields: { username: m.fields.username, password: m.fields.password },
      path: "",
    };
  }
  if (m.kind === "save_candidate") {
    if (
      typeof m.username !== "string" ||
      typeof m.password !== "string" ||
      (m.candidate !== "login" && m.candidate !== "change")
    ) {
      return null;
    }
    return {
      kind: "save_candidate",
      username: m.username,
      password: m.password,
      candidate: m.candidate,
      path: "",
    };
  }
  return null;
}
